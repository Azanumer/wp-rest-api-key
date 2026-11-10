<?php
/**
 * Uninstall REST API Key Authentication.
 *
 * Drops the keys table. Any key a client still holds stops working the
 * moment the table is gone — that is the point.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'rest_api_keys' );
