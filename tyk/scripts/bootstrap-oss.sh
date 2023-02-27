./tyk/scripts/wait-for-it.sh -t 300 localhost:8080/hello
sleep 1;
status=$(curl -s -o /dev/null -w "%{http_code}" localhost:8080/hello)

if [ "200" == "$status" ]; then

  # Create httpbin API
  curl -s -X POST localhost:8080/tyk/apis \
    --header "X-Tyk-Authorization: 352d20ee67be67f6340b4c0605b044b7" \
    --data "{
        \"jwt_issued_at_validation_skew\": 0,
        \"upstream_certificates\": {},
        \"use_keyless\": true,
        \"enable_coprocess_auth\": false,
        \"base_identity_provided_by\": \"\",
        \"custom_middleware\": {
          \"pre\": [
            {
              \"name\": \"AddFooBarHeader\",
              \"path\": \"/opt/tyk-gateway/middleware/CustomGoPlugin.so\",
              \"require_session\": false,
              \"raw_body_only\": false
            }
          ],
          \"post\": [],
          \"post_key_auth\": [],
          \"auth_check\": {
            \"name\": \"\",
            \"path\": \"\",
            \"require_session\": false,
            \"raw_body_only\": false
          },
          \"response\": [],
          \"driver\": \"goplugin\",
          \"id_extractor\": {
            \"extract_from\": \"\",
            \"extract_with\": \"\",
            \"extractor_config\": {}
          }
        },
        \"disable_quota\": false,
        \"custom_middleware_bundle\": \"\",
        \"cache_options\": {
          \"cache_timeout\": 60,
          \"enable_cache\": true,
          \"cache_all_safe_requests\": false,
          \"cache_response_codes\": [],
          \"enable_upstream_cache_control\": false,
          \"cache_control_ttl_header\": \"\",
          \"cache_by_headers\": []
        },
        \"enable_ip_blacklisting\": false,
        \"tag_headers\": [],
        \"jwt_scope_to_policy_mapping\": {},
        \"pinned_public_keys\": {},
        \"expire_analytics_after\": 0,
        \"external_oauth\": {
          \"enabled\": false,
          \"providers\": []
        },
        \"domain\": \"\",
        \"openid_options\": {
          \"providers\": [],
          \"segregate_by_client\": false
        },
        \"jwt_policy_field_name\": \"\",
        \"enable_proxy_protocol\": false,
        \"jwt_default_policies\": [],
        \"active\": true,
        \"jwt_expires_at_validation_skew\": 0,
        \"config_data\": {},
        \"notifications\": {
          \"shared_secret\": \"\",
          \"oauth_on_keychange_url\": \"\"
        },
        \"jwt_client_base_field\": \"\",
        \"auth\": {
          \"disable_header\": false,
          \"auth_header_name\": \"Authorization\",
          \"cookie_name\": \"\",
          \"name\": \"\",
          \"validate_signature\": false,
          \"use_param\": false,
          \"signature\": {
            \"algorithm\": \"\",
            \"header\": \"\",
            \"use_param\": false,
            \"param_name\": \"\",
            \"secret\": \"\",
            \"allowed_clock_skew\": 0,
            \"error_code\": 0,
            \"error_message\": \"\"
          },
          \"use_cookie\": false,
          \"param_name\": \"\",
          \"use_certificate\": false
        },
        \"check_host_against_uptime_tests\": false,
        \"auth_provider\": {
          \"name\": \"\",
          \"storage_engine\": \"\",
          \"meta\": {}
        },
        \"blacklisted_ips\": [],
        \"graphql\": {
          \"schema\": \"\",
          \"enabled\": false,
          \"engine\": {
            \"field_configs\": [],
            \"data_sources\": []
          },
          \"type_field_configurations\": [],
          \"execution_mode\": \"proxyOnly\",
          \"proxy\": {
            \"auth_headers\": {}
          },
          \"subgraph\": {
            \"sdl\": \"\"
          },
          \"supergraph\": {
            \"subgraphs\": [],
            \"merged_sdl\": \"\",
            \"global_headers\": {},
            \"disable_query_batching\": false
          },
          \"version\": \"2\",
          \"playground\": {
            \"enabled\": false,
            \"path\": \"\"
          }
        },
        \"hmac_allowed_clock_skew\": -1,
        \"dont_set_quota_on_create\": false,
        \"uptime_tests\": {
          \"check_list\": [],
          \"config\": {
            \"expire_utime_after\": 0,
            \"service_discovery\": {
              \"use_discovery_service\": false,
              \"query_endpoint\": \"\",
              \"use_nested_query\": false,
              \"parent_data_path\": \"\",
              \"data_path\": \"\",
              \"cache_timeout\": 60
            },
            \"recheck_wait\": 0
          }
        },
        \"enable_jwt\": false,
        \"do_not_track\": false,
        \"name\": \"httpbin\",
        \"slug\": \"httpbin\",
        \"analytics_plugin\": {},
        \"oauth_meta\": {
          \"allowed_access_types\": [],
          \"allowed_authorize_types\": [],
          \"auth_login_redirect\": \"\"
        },
        \"CORS\": {
          \"enable\": false,
          \"max_age\": 24,
          \"allow_credentials\": false,
          \"exposed_headers\": [],
          \"allowed_headers\": [
            \"Origin\",
            \"Accept\",
            \"Content-Type\",
            \"X-Requested-With\",
            \"Authorization\"
          ],
          \"options_passthrough\": false,
          \"debug\": false,
          \"allowed_origins\": [
            \"*\"
          ],
          \"allowed_methods\": [
            \"GET\",
            \"POST\",
            \"HEAD\"
          ]
        },
        \"event_handlers\": {
          \"events\": {}
        },
        \"proxy\": {
          \"target_url\": \"http://httpbin.org/\",
          \"service_discovery\": {
            \"endpoint_returns_list\": false,
            \"cache_timeout\": 0,
            \"parent_data_path\": \"\",
            \"query_endpoint\": \"\",
            \"use_discovery_service\": false,
            \"_sd_show_port_path\": false,
            \"target_path\": \"\",
            \"use_target_list\": false,
            \"use_nested_query\": false,
            \"data_path\": \"\",
            \"port_data_path\": \"\"
          },
          \"check_host_against_uptime_tests\": false,
          \"transport\": {
            \"ssl_insecure_skip_verify\": false,
            \"ssl_min_version\": 0,
            \"proxy_url\": \"\",
            \"ssl_ciphers\": []
          },
          \"target_list\": [],
          \"preserve_host_header\": false,
          \"strip_listen_path\": true,
          \"enable_load_balancing\": false,
          \"listen_path\": \"/httpbin/\",
          \"disable_strip_slash\": true
        },
        \"client_certificates\": [],
        \"use_basic_auth\": false,
        \"version_data\": {
          \"not_versioned\": true,
          \"default_version\": \"\",
          \"versions\": {
            \"Default\": {
              \"name\": \"Default\",
              \"expires\": \"\",
              \"paths\": {
                \"ignored\": [],
                \"white_list\": [],
                \"black_list\": []
              },
              \"use_extended_paths\": true,
              \"extended_paths\": {
                \"ignored\": [],
                \"white_list\": [],
                \"black_list\": [],
                \"transform\": [],
                \"transform_response\": [],
                \"transform_jq\": [],
                \"transform_jq_response\": [],
                \"transform_headers\": [],
                \"transform_response_headers\": [],
                \"hard_timeouts\": [],
                \"circuit_breakers\": [],
                \"url_rewrites\": [],
                \"virtual\": [],
                \"size_limits\": [],
                \"method_transforms\": [],
                \"track_endpoints\": [],
                \"do_not_track_endpoints\": [],
                \"validate_json\": [],
                \"internal\": [],
                \"persist_graphql\": []
              },
              \"global_headers\": {},
              \"global_headers_remove\": [],
              \"global_response_headers\": {},
              \"global_response_headers_remove\": [],
              \"ignore_endpoint_case\": false,
              \"global_size_limit\": 0,
              \"override_target\": \"\"
            }
          }
        },
        \"jwt_scope_claim_name\": \"\",
        \"use_standard_auth\": false,
        \"session_lifetime\": 0,
        \"hmac_allowed_algorithms\": [],
        \"disable_rate_limit\": false,
        \"definition\": {
          \"enabled\": false,
          \"name\": \"\",
          \"default\": \"\",
          \"location\": \"header\",
          \"key\": \"x-api-version\",
          \"strip_path\": false,
          \"strip_versioning_data\": false,
          \"versions\": {}
        },
        \"use_oauth2\": false,
        \"jwt_source\": \"\",
        \"jwt_signing_method\": \"\",
        \"jwt_not_before_validation_skew\": 0,
        \"use_go_plugin_auth\": false,
        \"jwt_identity_base_field\": \"\",
        \"allowed_ips\": [],
        \"request_signing\": {
          \"is_enabled\": false,
          \"secret\": \"\",
          \"key_id\": \"\",
          \"algorithm\": \"\",
          \"header_list\": [],
          \"certificate_id\": \"\",
          \"signature_header\": \"\"
        },
        \"enable_ip_whitelisting\": false,
        \"global_rate_limit\": {
          \"rate\": 0,
          \"per\": 0
        },
        \"protocol\": \"\",
        \"enable_context_vars\": false,
        \"tags\": [],
        \"basic_auth\": {
          \"disable_caching\": false,
          \"cache_ttl\": 0,
          \"extract_from_body\": false,
          \"body_user_regexp\": \"\",
          \"body_password_regexp\": \"\"
        },
        \"listen_port\": 0,
        \"session_provider\": {
          \"name\": \"\",
          \"storage_engine\": \"\",
          \"meta\": {}
        },
        \"auth_configs\": {
          \"authToken\": {
            \"disable_header\": false,
            \"auth_header_name\": \"Authorization\",
            \"cookie_name\": \"\",
            \"name\": \"\",
            \"validate_signature\": false,
            \"use_param\": false,
            \"signature\": {
              \"algorithm\": \"\",
              \"header\": \"\",
              \"use_param\": false,
              \"param_name\": \"\",
              \"secret\": \"\",
              \"allowed_clock_skew\": 0,
              \"error_code\": 0,
              \"error_message\": \"\"
            },
            \"use_cookie\": false,
            \"param_name\": \"\",
            \"use_certificate\": false
          },
          \"basic\": {
            \"disable_header\": false,
            \"auth_header_name\": \"Authorization\",
            \"cookie_name\": \"\",
            \"name\": \"\",
            \"validate_signature\": false,
            \"use_param\": false,
            \"signature\": {
              \"algorithm\": \"\",
              \"header\": \"\",
              \"use_param\": false,
              \"param_name\": \"\",
              \"secret\": \"\",
              \"allowed_clock_skew\": 0,
              \"error_code\": 0,
              \"error_message\": \"\"
            },
            \"use_cookie\": false,
            \"param_name\": \"\",
            \"use_certificate\": false
          },
          \"coprocess\": {
            \"disable_header\": false,
            \"auth_header_name\": \"Authorization\",
            \"cookie_name\": \"\",
            \"name\": \"\",
            \"validate_signature\": false,
            \"use_param\": false,
            \"signature\": {
              \"algorithm\": \"\",
              \"header\": \"\",
              \"use_param\": false,
              \"param_name\": \"\",
              \"secret\": \"\",
              \"allowed_clock_skew\": 0,
              \"error_code\": 0,
              \"error_message\": \"\"
            },
            \"use_cookie\": false,
            \"param_name\": \"\",
            \"use_certificate\": false
          },
          \"hmac\": {
            \"disable_header\": false,
            \"auth_header_name\": \"Authorization\",
            \"cookie_name\": \"\",
            \"name\": \"\",
            \"validate_signature\": false,
            \"use_param\": false,
            \"signature\": {
              \"algorithm\": \"\",
              \"header\": \"\",
              \"use_param\": false,
              \"param_name\": \"\",
              \"secret\": \"\",
              \"allowed_clock_skew\": 0,
              \"error_code\": 0,
              \"error_message\": \"\"
            },
            \"use_cookie\": false,
            \"param_name\": \"\",
            \"use_certificate\": false
          },
          \"jwt\": {
            \"disable_header\": false,
            \"auth_header_name\": \"Authorization\",
            \"cookie_name\": \"\",
            \"name\": \"\",
            \"validate_signature\": false,
            \"use_param\": false,
            \"signature\": {
              \"algorithm\": \"\",
              \"header\": \"\",
              \"use_param\": false,
              \"param_name\": \"\",
              \"secret\": \"\",
              \"allowed_clock_skew\": 0,
              \"error_code\": 0,
              \"error_message\": \"\"
            },
            \"use_cookie\": false,
            \"param_name\": \"\",
            \"use_certificate\": false
          },
          \"oauth\": {
            \"disable_header\": false,
            \"auth_header_name\": \"Authorization\",
            \"cookie_name\": \"\",
            \"name\": \"\",
            \"validate_signature\": false,
            \"use_param\": false,
            \"signature\": {
              \"algorithm\": \"\",
              \"header\": \"\",
              \"use_param\": false,
              \"param_name\": \"\",
              \"secret\": \"\",
              \"allowed_clock_skew\": 0,
              \"error_code\": 0,
              \"error_message\": \"\"
            },
            \"use_cookie\": false,
            \"param_name\": \"\",
            \"use_certificate\": false
          },
          \"oidc\": {
            \"disable_header\": false,
            \"auth_header_name\": \"Authorization\",
            \"cookie_name\": \"\",
            \"name\": \"\",
            \"validate_signature\": false,
            \"use_param\": false,
            \"signature\": {
              \"algorithm\": \"\",
              \"header\": \"\",
              \"use_param\": false,
              \"param_name\": \"\",
              \"secret\": \"\",
              \"allowed_clock_skew\": 0,
              \"error_code\": 0,
              \"error_message\": \"\"
            },
            \"use_cookie\": false,
            \"param_name\": \"\",
            \"use_certificate\": false
          }
        },
        \"strip_auth_data\": false,
        \"certificates\": [],
        \"enable_signature_checking\": false,
        \"use_openid\": false,
        \"internal\": false,
        \"jwt_skip_kid\": false,
        \"enable_batch_request_support\": false,
        \"enable_detailed_recording\": true,
        \"scopes\": {
          \"jwt\": {},
          \"oidc\": {}
        },
        \"response_processors\": [],
        \"use_mutual_tls_auth\": false
    }" > /dev/null

   # Create httpbin API
  curl -s localhost:8080/tyk/reload \
    --header "X-Tyk-Authorization: 352d20ee67be67f6340b4c0605b044b7"

fi
