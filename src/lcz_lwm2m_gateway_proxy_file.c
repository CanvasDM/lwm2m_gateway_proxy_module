/**
 * @file lcz_lwm2m_gateway_proxy_file.c
 * @brief CoAP file proxy
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_gateway_proxy_file, CONFIG_LCZ_LWM2M_GATEWAY_PROXY_LOG_LEVEL);

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/lwm2m.h>
#include <lwm2m_engine.h>
#include <lwm2m_transport.h>

#include <file_system_utilities.h>
#include <lcz_coap_helpers.h>
#include <lcz_lwm2m_fw_update.h>

#include "lcz_lwm2m_gateway_proxy.h"
#include "lcz_lwm2m_gateway_proxy_file.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define PROXY_CACHE_BASE_DIR CONFIG_LCZ_PARAM_FILE_MOUNT_POINT
#define PROXY_CACHE_CACHE_DIR CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_DIRECTORY
#define PROXY_CACHE_FILE_PATH PROXY_CACHE_BASE_DIR "/" PROXY_CACHE_CACHE_DIR

/* We don't retry any of the proxied CoAP messages, but need to init the retries field */
#define COAP_RETRIES_INIT 1

typedef struct {
	uint8_t *uri;
	int64_t time_added;
	char file_path[CONFIG_FSU_MAX_FILE_NAME_SIZE];
	uint32_t file_size;
	uint32_t file_position;
} PROXY_CACHE_ENTRY_T;

/* Mapping from SZX value in Block2 option to block size */
static const uint16_t BLOCK_SIZE[8] = {
	16, 32, 64, 128, 256, 512, 1024, 0,
};
#define BLOCK_SIZE(block2) (BLOCK_SIZE[(block2)&0x7])
#define BLOCK_NUM(block2) ((block2) >> 4)
#define BLOCK_MORE 0x8

/* Maximum size of block to support */
#define PROXY_BLOCK_MAX CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_BLOCK_SIZE

/* How often to check cache for expired entries */
#define MANAGE_CACHE_PERIOD (30 * MSEC_PER_SEC)

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static void coap_file_proxy_start(void);
static void file_proxy_timeout_work_handler(struct k_work *work);
static int file_proxy_reply(const struct coap_packet *response, struct coap_reply *reply,
			    const struct sockaddr *from);
static PROXY_CACHE_ENTRY_T *cache_lookup_uri(char *uri);
static PROXY_CACHE_ENTRY_T *cache_entry_new(char *uri);
static enum lwm2m_coap_resp service_request(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx,
					    PROXY_CACHE_ENTRY_T *entry, struct coap_packet *request,
					    struct coap_packet *ack);
static int forward_request(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, PROXY_CACHE_ENTRY_T *entry,
			   struct coap_packet *request);
static void manage_cache(uint32_t tag);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static struct lwm2m_ctx coap_file_proxy_ctx;
static bool coap_file_proxy_running = false;

static K_MUTEX_DEFINE(file_proxy_mutex);
static K_WORK_DELAYABLE_DEFINE(file_proxy_timeout_work, file_proxy_timeout_work_handler);

static PROXY_CACHE_ENTRY_T proxy_cache_meta[CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM];

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_lwm2m_gateway_file_proxy_init(void)
{
	/* Create the directory for proxy files */
	if (fsu_mkdir(PROXY_CACHE_BASE_DIR, PROXY_CACHE_CACHE_DIR) < 0) {
		LOG_ERR("Could not create proxy cache directory");
	}

	/* Register a service to periodically maintain our cache */
	lwm2m_engine_add_service(manage_cache, MANAGE_CACHE_PERIOD, 0);
}

enum lwm2m_coap_resp lcz_lwm2m_gateway_file_proxy_request(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx,
							  struct coap_packet *request,
							  struct coap_packet *ack)
{
	PROXY_CACHE_ENTRY_T *entry;
	uint8_t uri[CONFIG_LWM2M_SWMGMT_PACKAGE_URI_LEN];
	enum lwm2m_coap_resp ret = LWM2M_COAP_RESP_NONE;

	if (lcz_coap_find_proxy_uri(request, uri, sizeof(uri)) == false) {
		/* Should never happen */
		LOG_ERR("File proxy request recevied without proxy URI");
	} else {
		/* Acquire a lock for our data */
		k_mutex_lock(&file_proxy_mutex, K_FOREVER);

		/* Check the cache for the file */
		entry = cache_lookup_uri(uri);
		if (entry) {
			ret = service_request(pctx, entry, request, ack);

			/*
			 * If the above function didn't return an ACK message, it means
			 * that the request was for a portion of the file that we have
			 * not yet downloaded from the server.
			 */
			if (ret == LWM2M_COAP_RESP_NONE) {
				/* Open a proxy connection */
				if (coap_file_proxy_running == false) {
					coap_file_proxy_start();
				}

				/* Forward the request */
				if (coap_file_proxy_running) {
					forward_request(pctx, entry, request);
				} else {
					/* Return an error if we couldn't establish the connection */
					ack->data[COAP_REPLY_BYTE] =
						COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE;
					ret = LWM2M_COAP_RESP_ACK;
				}
			}
		} else if (coap_file_proxy_running == false) {
			/* Else, the URI is not in our cache. Try to create a new entry. */
			entry = cache_entry_new(uri);

			/* If we were successful, try to open a proxy connection */
			if (entry != NULL) {
				/* Open a proxy connection */
				coap_file_proxy_start();

				/* Forward the request */
				if (coap_file_proxy_running) {
					forward_request(pctx, entry, request);
				} else {
					/* Return an error if we couldn't establish the connection */
					ack->data[COAP_REPLY_BYTE] =
						COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE;
					ret = LWM2M_COAP_RESP_ACK;
				}
			} else {
				/* Else, the cache is full */
				ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_NOT_ALLOWED;
				ret = LWM2M_COAP_RESP_ACK;
			}
		} else {
			/* Else, file not in cache and the proxy connection is busy */
			ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE;
			ret = LWM2M_COAP_RESP_ACK;
		}

		/* Release the lock */
		k_mutex_unlock(&file_proxy_mutex);
	}

	return ret;
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/** @brief Start a CoAP file proxy session with the network CoAP proxy */
static void coap_file_proxy_start(void)
{
	static char proxy_uri[CONFIG_LWM2M_SWMGMT_PACKAGE_URI_LEN];
	int ret = 0;
	const char *server_addr;

	/* Initialize the transport */
	memset(&coap_file_proxy_ctx, 0, sizeof(coap_file_proxy_ctx));
	coap_file_proxy_ctx.transport_name = "udp";
	coap_file_proxy_ctx.load_credentials = lcz_lwm2m_fw_update_load_certs;
	coap_file_proxy_ctx.tls_tag = CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_TLS_TAG;
	lwm2m_engine_context_init(&coap_file_proxy_ctx);

	server_addr = lwm2m_firmware_get_proxy_uri();
	if (server_addr == NULL) {
		LOG_ERR("Proxy URI is required for CoAP proxy");
		ret = -EINVAL;
	} else if (strlen(server_addr) >= CONFIG_LWM2M_SWMGMT_PACKAGE_URI_LEN) {
		LOG_ERR("Proxy URI too long: %s", server_addr);
		ret = -EINVAL;
	}

	if (ret == 0) {
		/* Copy required as it gets modified when port is available */
		strcpy(proxy_uri, server_addr);

		/* Load the URI */
		ret = lwm2m_transport_setup(&coap_file_proxy_ctx, proxy_uri, true);
		if (ret < 0) {
			LOG_ERR("Failed to parse server URI.");
		}
	}

	/* Start the transport */
	if (ret >= 0) {
		ret = lwm2m_transport_start(&coap_file_proxy_ctx);
		if (ret < 0) {
			LOG_ERR("Cannot start a firmware-pull connection:%d", ret);
		}
	}

	if (ret >= 0) {
		lcz_lwm2m_gateway_proxy_add_context(&coap_file_proxy_ctx);
		coap_file_proxy_running = true;
	}

	k_work_schedule(&file_proxy_timeout_work,
			K_SECONDS(CONFIG_LCZ_LWM2M_GATEWAY_FILE_PROXY_TIMEOUT_SECONDS));
}

/** @brief Work handler for proxy session timeout
 *
 * This function will be called when the proxy session timeout expires. The function
 * will close the session.
 *
 * @param[in] work Work item
 */
static void file_proxy_timeout_work_handler(struct k_work *work)
{
	/* Acquire a lock for our data */
	k_mutex_lock(&file_proxy_mutex, K_FOREVER);

	/* Close the proxy context */
	lwm2m_engine_stop(&coap_file_proxy_ctx);

	/* Clear the flag */
	coap_file_proxy_running = false;

	/* Release the lock */
	k_mutex_unlock(&file_proxy_mutex);
}

/** @brief Callback for reply to CoAP proxy request
 *
 * This function is called on the reply from the network CoAP proxy server in response
 * to a request. The reply is also always sent back to our client (BLE peripheral) that
 * made the request. The handling here in this function is to update the cached file
 * in the file system while the client receives the file in parallel.
 *
 * @param[in] response A pointer to the CoAP response from the network CoAP server
 * @param[in] reply A pointer to the reply structure that was tracking this response
 * @param[in] from Socket address for the source of the response packet
 *
 * @returns 0 (does not report errors through the return value)
 */
static int file_proxy_reply(const struct coap_packet *response, struct coap_reply *reply,
			    const struct sockaddr *from)
{
	ARG_UNUSED(from);
	PROXY_CACHE_ENTRY_T *entry = (PROXY_CACHE_ENTRY_T *)reply->user_data;
	uint32_t block2;
	uint32_t size2;
	uint32_t offset;
	struct fs_file_t f;
	int r;
	const uint8_t *data_ptr;
	uint16_t data_len;

	/* Acquire a lock for our data */
	k_mutex_lock(&file_proxy_mutex, K_FOREVER);

	if (lcz_coap_get_option_int((struct coap_packet *)response, COAP_OPTION_BLOCK2, &block2) ==
	    false) {
		LOG_ERR("Proxy response received without Block2 option");
	} else {
		offset = BLOCK_NUM(block2) * BLOCK_SIZE(block2);
		if (entry != NULL) {
			/* Save the file size if it was provided */
			if (lcz_coap_get_option_int((struct coap_packet *)response,
						    COAP_OPTION_SIZE2, &size2)) {
				if (entry->file_size != 0 && entry->file_size != size2) {
					LOG_WRN("File size changed from %d to %d", entry->file_size,
						size2);
				}
				entry->file_size = size2;
			}

			/* Make sure that the new block goes where we expect */
			if (offset != entry->file_position) {
				LOG_ERR("New block offset (%d) isn't aligned with cache position (%d)",
					offset, entry->file_position);
			} else {
				fs_file_t_init(&f);
				r = fs_open(&f, entry->file_path, FS_O_WRITE | FS_O_CREATE);
				if (r < 0) {
					LOG_ERR("Failed to open cache file %s for writing: %d",
						entry->file_path, r);
				} else {
					/* Seek to the requested offset */
					r = fs_seek(&f, offset, FS_SEEK_SET);
					if (r < 0) {
						LOG_ERR("Failed to seek to position %d in cache file %s: %d",
							offset, entry->file_path, r);
					} else {
						/* Write the packet data to the file */
						data_ptr = coap_packet_get_payload(response,
										   &data_len);
						r = fs_write(&f, data_ptr, data_len);
						if (r < 0) {
							LOG_ERR("Failed to write %d bytes to cache file %s: %d",
								data_len, entry->file_path, r);
						} else {
							entry->file_position += data_len;
						}
					}

					/* Close the file */
					r = fs_close(&f);
					if (r < 0) {
						LOG_ERR("Failed to close cache file %s: %d",
							entry->file_path, r);
					}
				}
			}
		}
	}

	/* Release the lock */
	k_mutex_unlock(&file_proxy_mutex);

	return 0;
}

/** @brief Look up a URI in the proxy cache
 *
 * @param[in] uri URI for which to search
 *
 * @returns the proxy cache entry for the URI or NULL if the URI was not in the cache
 */
static PROXY_CACHE_ENTRY_T *cache_lookup_uri(char *uri)
{
	int i;

	/* Search for the URI in our cache */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM; i++) {
		if (proxy_cache_meta[i].uri != NULL && strcmp(proxy_cache_meta[i].uri, uri) == 0) {
			break;
		}
	}

	/* Return the entry that was found */
	if (i >= CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM) {
		return NULL;
	} else {
		return &(proxy_cache_meta[i]);
	}
}

/** @brief Create a new entry in the proxy cache for a URI
 *
 * @param[in] uri URI to be added to the cache
 *
 * @returns the proxy cache entry for the URI or NULL if there was no space in the cache
 */
static PROXY_CACHE_ENTRY_T *cache_entry_new(char *uri)
{
	int i;

	/* Look for an empty spot in the cache */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM; i++) {
		if (proxy_cache_meta[i].uri == NULL) {
			break;
		}
	}

	/* Fill in the new entry */
	if (i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM) {
		proxy_cache_meta[i].uri = k_malloc(strlen(uri) + 1);
		if (proxy_cache_meta[i].uri != NULL) {
			/* Copy the URI */
			strcpy(proxy_cache_meta[i].uri, uri);

			/* Assign a file name */
			snprintf(proxy_cache_meta[i].file_path,
				 sizeof(proxy_cache_meta[0].file_path),
				 PROXY_CACHE_FILE_PATH "/%d.bin", i);

			/* Delete the file in case it exists */
			fs_unlink(proxy_cache_meta[i].file_path);

			/* Empty file for now */
			proxy_cache_meta[i].file_size = 0;
			proxy_cache_meta[i].file_position = 0;

			/* Add timestamp */
			proxy_cache_meta[i].time_added = k_uptime_get();
		} else {
			i = CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM;
		}
	}

	/* Return the entry that was created */
	if (i >= CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM) {
		return NULL;
	} else {
		return &(proxy_cache_meta[i]);
	}
}

/** @brief Service a request for a file out of our cache
 *
 * @param[in] pctx Gateway proxy context from which the request came
 * @param[in] entry Our cache entry from which we're serving
 * @param[in] request Incoming CoAP request packet from the client
 * @param[in] ack Location for any reply that we might build
 *
 * @returns LWM2M_COAP_RESP_NONE if no reply should be sent, LWM2M_COAP_RESP_ACK if
 * the CoAP ACK message was populated and should be sent as a reply, or
 * LWM2M_COAP_RESP_NOT_HANDLED if the received CoAP message was not processed and
 * the LwM2M engine should attempt to process it.
 */
static enum lwm2m_coap_resp service_request(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx,
					    PROXY_CACHE_ENTRY_T *entry, struct coap_packet *request,
					    struct coap_packet *ack)
{
	static uint8_t block_buffer[PROXY_BLOCK_MAX];
	enum lwm2m_coap_resp ret = LWM2M_COAP_RESP_NONE;
	uint32_t block2 = 0;
	uint32_t offset = BLOCK_NUM(block2) * BLOCK_SIZE(block2);
	uint32_t size;
	struct fs_file_t f;
	int r;

	/* Get the Block2 option value from the message */
	lcz_coap_get_option_int(request, COAP_OPTION_BLOCK2, &block2);
	offset = BLOCK_NUM(block2) * BLOCK_SIZE(block2);

	/* Reject the request if the block size doesn't match our buffer */
	if (BLOCK_SIZE(block2) != sizeof(block_buffer)) {
		LOG_ERR("Proxy block request (%d) doesn't match our buffer size (%d)",
			BLOCK_SIZE(block2), sizeof(block_buffer));
		ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_BAD_REQUEST;
		ret = LWM2M_COAP_RESP_ACK;
	}

	/* Reject if the offset is beyond the end of the file */
	if (ret == LWM2M_COAP_RESP_NONE && offset >= entry->file_size) {
		LOG_ERR("Proxy block request offset (%d) is beyond file length (%d)", offset,
			entry->file_size);
		ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_BAD_REQUEST;
		ret = LWM2M_COAP_RESP_ACK;
	}

	/* Check to see if we have the piece of the file that the client requests */
	if ((ret == LWM2M_COAP_RESP_NONE) &&
	    (entry->file_position >= (offset + BLOCK_SIZE(block2)))) {
		/* Add the Block2 option to the message */
		if (offset + BLOCK_SIZE(block2) < entry->file_size) {
			block2 |= BLOCK_MORE;
		}
		coap_append_option_int(ack, COAP_OPTION_BLOCK2, block2);

		/* On the first request, add the Size2 option */
		if (offset == 0) {
			coap_append_option_int(ack, COAP_OPTION_SIZE2, entry->file_size);
		}

		/* Adjust the block size */
		size = sizeof(block_buffer);
		if ((entry->file_size - offset) < size) {
			size = (entry->file_size - offset);
		}

		/* Open the cache file */
		fs_file_t_init(&f);
		r = fs_open(&f, entry->file_path, FS_O_READ);
		if (r < 0) {
			LOG_ERR("Failed to open cache file %s for reading: %d", entry->file_path,
				r);
			ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_NOT_FOUND;
		} else {
			/* Seek to the requested offset */
			r = fs_seek(&f, offset, FS_SEEK_SET);
			if (r < 0) {
				LOG_ERR("Failed to seek to position %d in cache file %s: %d",
					offset, entry->file_path, r);
				ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_NOT_FOUND;
			} else {
				/* Read the requested block */
				r = fs_read(&f, block_buffer, size);
				if (r < 0) {
					LOG_ERR("Failed to read cache file %s: %d",
						entry->file_path, r);
					ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_NOT_FOUND;
				}
			}

			/* Add the payload to the message */
			if (r >= 0) {
				ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_CONTENT;
				coap_packet_append_payload_marker(ack);
				coap_packet_append_payload(ack, block_buffer, size);
			}

			/* Close the file */
			r = fs_close(&f);
			if (r < 0) {
				LOG_ERR("Failed to close cache file %s: %d", entry->file_path, r);
			}
		}

		ret = LWM2M_COAP_RESP_ACK;
	}

	return ret;
}

/** @brief Forward a request from a client to the network server
 *
 * @param[in] pctx Gateway proxy context from which the request came
 * @param[in] entry Our cache entry associated with the request
 * @param[in] request Incoming CoAP request packet from the client
 *
 * @returns 0 on success, <0 on error.
 */
static int forward_request(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, PROXY_CACHE_ENTRY_T *entry,
			   struct coap_packet *request)
{
	struct coap_pending *pending;
	struct coap_reply *reply;
	int ret = 0;

	/* Send the packet to the server */
	lwm2m_engine_send_coap(&coap_file_proxy_ctx, request);
	k_work_reschedule(&file_proxy_timeout_work,
			  K_SECONDS(CONFIG_LCZ_LWM2M_GATEWAY_FILE_PROXY_TIMEOUT_SECONDS));

	/* If this message expects an ACK from the server, add it to a pending list */
	if (coap_header_get_type(request) == COAP_TYPE_CON) {
		pending = coap_pending_next_unused(pctx->pendings, CONFIG_LWM2M_ENGINE_MAX_PENDING);
		if (pending == NULL) {
			LOG_ERR("Unable to find free pending slot");
			ret = -ENOMEM;
		} else {
			ret = coap_pending_init(pending, request, NULL, COAP_RETRIES_INIT);
			if (ret < 0) {
				LOG_ERR("Unable to initialize pending: %d", ret);
			} else {
				coap_pending_cycle(pending);
			}
		}

		/* Also track the reply to this message */
		reply = coap_reply_next_unused(pctx->replies, CONFIG_LWM2M_ENGINE_MAX_REPLIES);
		if (reply == NULL) {
			LOG_ERR("Unable to find free reply slot");
			ret = -ENOMEM;
		} else {
			coap_reply_init(reply, request);
			reply->reply = file_proxy_reply;
			reply->user_data = entry;
		}
	}

	return ret;
}

/** @brief Service callback for managing the cache
 *
 * This function is called periodically (MANAGE_CACHE_PERIOD) to check to make sure
 * that everything in the cache is up to date. If there are entries in the cache that
 * are too old, they will be removed.
 *
 * @param[in] tag Service tag (unused)
 */
static void manage_cache(uint32_t tag)
{
	ARG_UNUSED(tag);
	int64_t now = k_uptime_get();
	int i;

	/* Search the cache for entries that are too old */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE_NUM; i++) {
		if (proxy_cache_meta[i].uri != NULL &&
		    (now - proxy_cache_meta[i].time_added) >=
			    (CONFIG_LCZ_LWM2M_GATEWAY_FILE_PROXY_CACHE_LIFETIME_SECONDS *
			     MSEC_PER_SEC)) {
			/* Free the entry since it is too old */
			k_free(proxy_cache_meta[i].uri);
			proxy_cache_meta[i].uri = NULL;
		}
	}
}
