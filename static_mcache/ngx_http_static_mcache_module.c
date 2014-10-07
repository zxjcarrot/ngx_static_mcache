
/*
 * Copyright (C) Xinjing Cho
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct{
	/* must be the first member */
	ngx_rbtree_node_t	node;
	ngx_str_t 			path;
	ngx_buf_t 			buf;
	ngx_queue_t			queue;
	time_t 				accessed;
} ngx_http_static_mcache_node_t;

typedef struct{
	ngx_rbtree_t 		rbtree;
	ngx_queue_t			expire_queue;
	ngx_rbtree_node_t	sentinel;
} ngx_http_static_mcache_shctx_t;

typedef struct{
	ngx_http_static_mcache_shctx_t 	*shctx;
	ngx_slab_pool_t 				*shpool;
} ngx_http_static_mcache_ctx_t;

typedef struct{
	ngx_shm_zone_t		*shm_zone;
	time_t 				inactive;
} ngx_http_static_mcache_conf_t;

static char *ngx_http_static_mcache_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_static_mcache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_static_mcache_init_zone(ngx_shm_zone_t *shm_zone,
 	void *data);

static void	* ngx_http_static_mcache_create_loc_conf(ngx_conf_t *cf);
static ngx_http_static_mcache_node_t *
ngx_http_static_mcache_cache_find(ngx_http_static_mcache_ctx_t * ctx,
								   ngx_str_t *path);

static void
ngx_http_static_mcache_rbtree_insert_value(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_http_static_mcache_node_t *
ngx_http_static_mcache_cache_insert(ngx_http_static_mcache_ctx_t * ctx,
								     ngx_str_t *path, ngx_uint_t buf_size);
static void
ngx_http_static_mcache_cache_delete(ngx_http_static_mcache_ctx_t  * ctx,
								     ngx_http_static_mcache_node_t * node);
static void
ngx_http_static_mcache_cache_access(ngx_http_static_mcache_ctx_t  * ctx,
								     ngx_http_static_mcache_node_t * node);
static void
ngx_http_static_mcache_expire_inactive(ngx_http_static_mcache_ctx_t  * ctx,
									   time_t inactive);

static ngx_int_t
ngx_http_static_mcache_read_file(ngx_open_file_info_t * of,
								 ngx_buf_t * buf);
static ngx_int_t ngx_http_static_mcache_hanlder(ngx_http_request_t *r);
static ngx_int_t ngx_http_static_mcache_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_static_mcache_commands[] = {
	{
		ngx_string("static_mcache_zone"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_http_static_mcache_zone,
		0,
		0,
		NULL
	},
	{
		ngx_string("static_mcache"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
		ngx_http_static_mcache,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t  ngx_http_static_mcache_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_static_mcache_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_static_mcache_create_loc_conf,/* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_static_mcache_module = {
    NGX_MODULE_V1,
    &ngx_http_static_mcache_module_ctx,     /* module context */
    ngx_http_static_mcache_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
static char *
ngx_http_static_mcache_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf) {
	ssize_t				 		  size;
	u_char 						 *p;
	ngx_str_t					 *value,name, s;
	ngx_shm_zone_t				 *shm_zone;
	ngx_http_static_mcache_ctx_t *ctx;

	value = cf->args->elts;

	if (cf->args->nelts == 2 && ngx_strncmp(value[1].data, "zone=", 5) == 0) {

		name.data = value[1].data + 5;

		p = (u_char *)ngx_strchr(name.data, ':');

		if (p == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
								"invalid zone size \"%V\"",
								 &value[1]);
			return NGX_CONF_ERROR;
		}
		
		name.len = p - name.data;

		s.data = p + 1;
		s.len = value[1].data + value[1].len - s.data;

		size = ngx_parse_size(&s);

		if (size == NGX_ERROR) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
								"invalid zone size \"%V\"",
								 &value[1]);
			return NGX_CONF_ERROR;
		}

	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
							"\"%V\" must have \"zone\" parameter", 
							&cmd->name);
		return NGX_CONF_ERROR;
	}

	if (name.len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
							"\"%V\" must have \"zone\" parameter", 
							&cmd->name);
		return NGX_CONF_ERROR;
	}

	shm_zone = ngx_shared_memory_add(cf, &name, size, 
									&ngx_http_static_mcache_module);

	if (shm_zone == NULL) {
		return NGX_CONF_ERROR;
	}

	if (shm_zone->data) {
		ctx = shm_zone->data;

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
							"\"%V \"%V\" is already bound to context %p", 
							&cmd->name, &name, ctx);
		return NGX_CONF_ERROR;
	}

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_static_mcache_ctx_t));

	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	shm_zone->init = ngx_http_static_mcache_init_zone;
	shm_zone->data = ctx;

	return NGX_CONF_OK;
}


static char *
ngx_http_static_mcache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf) {
	ngx_uint_t 		 				 i;
	ngx_shm_zone_t 					*shm_zone;
	ngx_str_t 						*value, zone_name, inactive_s;
	time_t						 	inactive;
	ngx_http_static_mcache_conf_t	*smcf = conf;

	value = cf->args->elts;
	for (i = 1; i < cf->args->nelts; ++i) {

		if (ngx_strncmp("zone=", value[i].data, 5) == 0) {

			zone_name.data = value[i].data + 5;
			zone_name.len = value[i].data + value[i].len - zone_name.data;

			if (zone_name.len == 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
									"\"%V\" must have \"zone\" parameter", 
									&cmd->name);
				return NGX_CONF_ERROR;
			}

			shm_zone = ngx_shared_memory_add(cf, &zone_name, 0, 
											&ngx_http_static_mcache_module);

			if (shm_zone == NULL) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
									"zone with name\"%V\" does not exist", 
									&zone_name);
				return NGX_CONF_ERROR;
			}

			smcf->shm_zone = shm_zone;
		}

		if (ngx_strncmp("inactive=", value[i].data, 9) == 0) {
			inactive_s.data = value[i].data + 9;
			inactive_s.len = value[i].data + value[i].len - inactive_s.data;

			inactive = ngx_parse_time(&inactive_s, 1);

			if (inactive == NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
									"invalid time value \"%V\"", 
									&value[i]);
				return NGX_CONF_ERROR;
			}

			smcf->inactive = inactive;
		}
	}
	
	if (smcf->shm_zone == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
							"\"%V\" must have \"zone\" parameter", 
							&cmd->name);
		return NGX_CONF_ERROR;
	}

	if (smcf->inactive == NGX_CONF_UNSET) {
		/* 1 hour inactive timeout as default */
		smcf->inactive = 3600;
	}

	return NGX_CONF_OK;
}
static ngx_int_t
ngx_http_static_mcache_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
	ngx_http_static_mcache_ctx_t *octx = data;
	ngx_http_static_mcache_ctx_t *ctx;
	size_t 					  	  len;

	ctx = shm_zone->data;
	
	if (octx) {
		/* we are being reloaded, use the old stuff.*/
		ctx->shctx = octx->shctx;
		ctx->shpool = octx->shpool;

		return NGX_OK;
	}

	ctx->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

	if (shm_zone->shm.exists) {
		ctx->shctx = ctx->shpool->data;

		return NGX_OK;
	}
	
	ctx->shctx = ngx_slab_alloc(ctx->shpool,
								sizeof(ngx_http_static_mcache_shctx_t));
	if (ctx->shctx == NULL) {
		return NGX_ERROR;
	}

	ctx->shpool->data = ctx->shctx;

	ngx_rbtree_init(&ctx->shctx->rbtree,
					&ctx->shctx->sentinel,
					ngx_http_static_mcache_rbtree_insert_value);

	ngx_queue_init(&ctx->shctx->expire_queue);

	len = sizeof(" in static_cache zone \"\"") + shm_zone->shm.name.len;

	ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);

	if (ctx->shpool->log_ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_sprintf(ctx->shpool->log_ctx, " in static_cache zone \"%V\"%Z",
				&shm_zone->shm.name);

	return NGX_OK;
}

static void	*
ngx_http_static_mcache_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_static_mcache_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_static_mcache_conf_t));
	if (conf == NULL) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0,
					  "failed to ngx_pcalloc for ngx_http_static_mcache_conf_t");
		return NULL;
	}
	/*
	* set by ngx_pcalloc()
	*
	* conf->shm_zone = NULL;
	*/
	conf->inactive = NGX_CONF_UNSET;

	return conf;
}

/* this function must be called with @ctx->shpool->mutex held */
static ngx_http_static_mcache_node_t *
ngx_http_static_mcache_cache_find(ngx_http_static_mcache_ctx_t * ctx,
								   ngx_str_t *path) {
	ngx_http_static_mcache_node_t  *mnode = NULL, *lrn;
	ngx_rbtree_node_t			   *node, *sentinel;
	ngx_int_t 					    res;

	sentinel = &ctx->shctx->sentinel;

	node = ctx->shctx->rbtree.root;

	for ( ;node != sentinel; ) {
		lrn = (ngx_http_static_mcache_node_t *)node;

		if (lrn->path.len == path->len) {

			res = ngx_filename_cmp(lrn->path.data,
								   path->data,
								   path->len);

			if (res == 0) {

				mnode = lrn;
				break;

			} else if (res < 0) {

				node = node->left;

			} else {

				node = node->right;

			}

		} else if (lrn->path.len < path->len) {

			node = node->left;

		} else {

			node = node->right;

		}

	}

	return mnode;
}

/* this function must be called with @ctx->shpool->mutex held */
static ngx_http_static_mcache_node_t *
ngx_http_static_mcache_cache_insert(ngx_http_static_mcache_ctx_t * ctx,
								   ngx_str_t *path, ngx_uint_t buf_size) {
	ngx_slab_pool_t 				*shpool = ctx->shpool;
	ngx_http_static_mcache_node_t 	*new;

	new = ngx_slab_calloc_locked(shpool, sizeof(ngx_http_static_mcache_node_t));
	
	if (new == NULL) {
		return NULL;
	}

	new->path.data = ngx_slab_alloc_locked(shpool, path->len);

	if (new->path.data == NULL) {
		ngx_slab_free_locked(shpool, new);
		return NULL;
	}

	ngx_memcpy(new->path.data, path->data, path->len);
	new->path.len = path->len;

	new->buf.start = ngx_slab_alloc_locked(shpool, buf_size);

	if (new->buf.start == NULL) {
		ngx_slab_free_locked(shpool, new->path.data);
		ngx_slab_free_locked(shpool, new);
		return NULL;
	}

	new->buf.end = new->buf.start + buf_size;
	new->buf.pos = new->buf.start;
	new->buf.last = new->buf.end;
	new->buf.memory = 1;
	new->buf.mmap = 1;

	ngx_rbtree_insert(&ctx->shctx->rbtree, &new->node);
	ngx_queue_insert_head(&ctx->shctx->expire_queue, &new->queue);
	new->accessed = ngx_time();

	return new;
}

/* this function must be called with @ctx->shpool->mutex held */
static void
ngx_http_static_mcache_cache_delete(ngx_http_static_mcache_ctx_t  * ctx,
								     ngx_http_static_mcache_node_t * node) {
	ngx_slab_pool_t 	*shpool = ctx->shpool;

	ngx_rbtree_delete(&ctx->shctx->rbtree, &node->node);
	
	ngx_slab_free_locked(shpool, node->buf.start);
	ngx_slab_free_locked(shpool, node->path.data);
	ngx_slab_free_locked(shpool, node);
}

/* this function must be called with @ctx->shpool->mutex held */
static void
ngx_http_static_mcache_cache_access(ngx_http_static_mcache_ctx_t  * ctx,
								     ngx_http_static_mcache_node_t * node) {
	node->accessed = ngx_time();

	ngx_queue_remove(&node->queue);
	ngx_queue_insert_head(&ctx->shctx->expire_queue, &node->queue);
}

/* this function must be called with @ctx->shpool->mutex held */
static void
ngx_http_static_mcache_expire_inactive(ngx_http_static_mcache_ctx_t  * ctx,
									   time_t inactive) {
	ngx_http_static_mcache_node_t	*node;
	ngx_queue_t 					*q;
	ngx_http_static_mcache_shctx_t 	*shctx = ctx->shctx;
	time_t 							 now;

	now = ngx_time();

	while (!ngx_queue_empty(&shctx->expire_queue)) {
		q = ngx_queue_last(&shctx->expire_queue);

		node = ngx_queue_data(q, ngx_http_static_mcache_node_t, queue);

		if (now - node->accessed < inactive) {
			return;
		}

		ngx_queue_remove(q);
		ngx_http_static_mcache_cache_delete(ctx, node);
	}
}
static ngx_int_t
ngx_http_static_mcache_read_file(ngx_open_file_info_t * of,
								 ngx_buf_t * buf) {
	off_t 		size;
	off_t 		nread; /* bytes read */
	ssize_t		n;

	nread = 0;
	size = ngx_buf_size(buf);

	while (nread < of->size) {
		n = ngx_read_fd(of->fd, buf->start + nread, size - nread);

		if (n == -1) {
			goto failed;
		}

		nread += n;
	}

	return NGX_OK;
failed:
	return NGX_ERROR;
}

static ngx_int_t
ngx_http_static_mcache_hanlder(ngx_http_request_t *r) {
	ngx_int_t 						 rc;
	ngx_str_t                  		 path;
	ngx_uint_t						 log_level, len, root;
	ngx_log_t                 		*log;
	u_char					  		*last, *location;
	ngx_buf_t						*b;
	ngx_chain_t						out;
	ngx_open_file_info_t			of;
	ngx_http_core_loc_conf_t		*clcf;
	ngx_shm_zone_t					*shm_zone;
	ngx_http_static_mcache_conf_t	*smcf;
	ngx_http_static_mcache_ctx_t 	*ctx;
	ngx_http_static_mcache_node_t	*cached_node;

	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST | NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	if (r->uri.data[r->uri.len - 1] == '/') {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
						  "static_mcache: uri ended with '/',hand it over to next module");
		/* hand it over to next module */
		return NGX_DECLINED;
	}

	log = r->connection->log;

	 /*
	 * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
	 * so we do not need to reserve memory for '/' for possible redirect
	 */

	last = ngx_http_map_uri_to_path(r, &path, &root, 0);

	path.len = last - path.data;

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	smcf = ngx_http_get_module_loc_conf(r, ngx_http_static_mcache_module);

	if(smcf == NULL){
		/* no directive set */
		return NGX_DECLINED;
	}

	ngx_memzero(&of, sizeof(ngx_open_file_info_t));

	of.read_ahead = clcf->read_ahead;
	of.directio = clcf->directio;
	of.valid = clcf->open_file_cache_valid;
	of.min_uses = clcf->open_file_cache_min_uses;
	of.errors = clcf->open_file_cache_errors;
	of.events = clcf->open_file_cache_events;

	if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) 
		!= NGX_OK) {
		switch (of.err) {
		
		case 0:
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		case NGX_ENOENT:
		case NGX_ENOTDIR:
		case NGX_ENAMETOOLONG:
			log_level = NGX_LOG_ERR;
			rc = NGX_HTTP_NOT_FOUND;
			break;

		case NGX_EACCES:
	#if (NGX_HAVE_OPENAT)
		case NGX_EMLINK:
		case NGX_ELOOP:
	#endif
			log_level = NGX_LOG_ERR;
			rc = NGX_HTTP_FORBIDDEN;
			break;
		default:
			log_level = NGX_LOG_CRIT;
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			break;
		}

		if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
			ngx_log_error(log_level, log, of.err,
						  "%s \"%s\" failed", of.failed, path.data);
		}

		return rc;
	}

	r->root_tested = !r->error_page;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);


	if (of.is_dir) {/* redirect to a url with '/' appended */
		ngx_log_error(NGX_LOG_EMERG, log, 0,
				  "static_mcache: file is directory, redirecting");

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

		ngx_http_clear_location(r);

		r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));

		if (r->headers_out.location == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		len = r->uri.len + 1;

		if (!clcf->alias && clcf->root_lengths == NULL && r->args.len == 0) {

			location = path.data + clcf->root.len;
			*last = '/';

		} else {
			if (r->args.len) {
				len += r->args.len + 1; /* 1 for '/' */
			}

			location = ngx_pnalloc(r->pool, len);

			if (location == NULL) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			ngx_memcpy(location, r->uri.data, r->uri.len);

			*last = '/';

			if (r->args.len) {
				*++last = '?';
				ngx_memcpy(++last, r->args.data, r->args.len);
			}
		}
		/*
		 * we do not need to set the r->headers_out.location->hash and
		 * r->headers_out.location->key fields
		 */

		r->headers_out.location->value.data = location;
		r->headers_out.location->value.len = len;

		return NGX_HTTP_MOVED_PERMANENTLY;
	}

#if !(NGX_WIN32)
	if (!of.is_file) {
		ngx_log_error(NGX_LOG_CRIT, log, 0,
					  "\"%s\" is not a regular file", path.data);
		return NGX_HTTP_NOT_FOUND;
	}
#endif

	if (r->method & NGX_HTTP_POST) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK) {
		return rc;
	}

	shm_zone = smcf->shm_zone;
	ctx = shm_zone->data;

	ngx_shmtx_lock(&ctx->shpool->mutex);
	/*
	ngx_log_error(NGX_LOG_CRIT, log, 0, 
				  "static_mcache: expiring inactive resources");
	*/
	ngx_http_static_mcache_expire_inactive(ctx, smcf->inactive);

	cached_node = ngx_http_static_mcache_cache_find(ctx, &path);

	if (cached_node == NULL) {
		/*
		ngx_log_error(NGX_LOG_EMERG, log, 0,
				  "static_mcache: file is not in the cache, inserting.");
		*/
		cached_node = ngx_http_static_mcache_cache_insert(ctx, &path, of.size);

		if (cached_node == NULL) {
			/*ngx_log_error(NGX_LOG_CRIT, log, 0, 
						  "shm_zone \"%V\" is out of memory, "
						  "resorting to static module.",
						  &shm_zone->shm.name);*/
			goto resort_to_static;
		}

		if (ngx_http_static_mcache_read_file(&of, &cached_node->buf) 
			!= NGX_OK) {
			/*ngx_log_error(NGX_LOG_CRIT, log, 0, 
						  "failed to read file into mcache with zone \"%V\"",
						  &shm_zone->shm.name);
			ngx_http_static_mcache_cache_delete(ctx, cached_node);*/
			goto resort_to_static;
		}
	}else{
		/*
		ngx_log_error(NGX_LOG_EMERG, log, 0,
				  "static_mcache: file is in the cache, good.");
		*/
	}

	ngx_http_static_mcache_cache_access(ctx, cached_node);

	ngx_shmtx_unlock(&ctx->shpool->mutex);
	
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

	if (b == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	b->start = cached_node->buf.start;

	//ngx_memcpy(b->start, cached_node->buf.start, of.size);

	log->action = "sending response to client";
/*
	ngx_log_error(NGX_LOG_CRIT, log, 0, 
				  "static_mcache: send static resource \"%V\","
				  "content_length_n %d", &path, of.size);
*/
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = of.size;
	r->headers_out.last_modified_time = of.mtime;

	if (ngx_http_set_etag(r) != NGX_OK) {
		ngx_pfree(r->pool, b->start);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_http_set_content_type(r) != NGX_OK) {
		ngx_pfree(r->pool, b->start);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (r != r->main && of.size == 0 ) {
		ngx_pfree(r->pool, b->start);
		return ngx_http_send_header(r);
	}

	r->allow_ranges = 1;

	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		ngx_pfree(r->pool, b->start);
		return rc;
	}

	/* set up buf & chain for response */
	b->memory = 1;
	b->end = b->start + of.size;
	b->pos = b->start;
	b->last = b->end;
	b->last_buf = 1;
	b->last_in_chain = 1;
	r->filter_need_temporary = 1;
	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);

//error:
	ngx_shmtx_unlock(&ctx->shpool->mutex);

	return NGX_HTTP_INTERNAL_SERVER_ERROR;

resort_to_static:/* hand it over to static module*/
	ngx_shmtx_unlock(&ctx->shpool->mutex);

	return NGX_DECLINED;
}

static void
ngx_http_static_mcache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
	ngx_int_t						res;
	ngx_rbtree_node_t				**p;
	ngx_http_static_mcache_node_t	*lrn, *lrnt;

	for ( ;; ) {
		lrn = (ngx_http_static_mcache_node_t *)node;
		lrnt = (ngx_http_static_mcache_node_t *)temp;
		/* TODO: use hash key to increase performance. */
		if (lrn->path.len == lrnt->path.len) {

			res = ngx_filename_cmp(lrn->path.data, lrnt->path.data, lrn->path.len);

			if (res < 0) {
				p = &temp->left;
			} else {
				p = &temp->right;
			}

		} else if (lrn->path.len < lrnt->path.len) {

			p = &temp->left;

		} else {

			p = &temp->right;

		}

		if (*p == sentinel) {
			break;
		}

		temp = *p;
	}

	*p = node;
	node->parent = temp;
	node->left = sentinel;
	node->right = sentinel;
	ngx_rbt_red(node);
}

static ngx_int_t
ngx_http_static_mcache_init(ngx_conf_t *cf) {
	ngx_http_handler_pt 		*h;
	ngx_http_core_main_conf_t	*cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_static_mcache_hanlder;

	return NGX_OK;
}