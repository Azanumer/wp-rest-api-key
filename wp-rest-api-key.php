<?php
/**
 * Plugin Name: REST API Key Authentication
 * Plugin URI: https://github.com/Azanumer/wp-rest-api-key
 * Description: Authenticate WordPress REST API requests with per-user API keys — X-API-Key header or ?api_key=, with read/write scopes and one-click revoke.
 * Version: 1.0.0
 * Author: Azan Umer
 * Author URI: https://azanumer.cv
 * License: MIT
 * License URI: https://opensource.org/licenses/mit-license.php
 * Text Domain: wrak
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WRAK_VERSION', '1.0.0' );
define( 'WRAK_KEY_PREFIX', 'rak_' );

/**
 * Table name for stored keys.
 *
 * @return string
 */
function wrak_table() {
	global $wpdb;
	return $wpdb->prefix . 'rest_api_keys';
}

/**
 * Create the keys table on activation.
 */
function wrak_activate() {
	global $wpdb;
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	$table   = wrak_table();
	$charset = $wpdb->get_charset_collate();
	$sql     = "CREATE TABLE {$table} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		user_id bigint(20) unsigned NOT NULL,
		label varchar(100) NOT NULL DEFAULT '',
		key_hash char(64) NOT NULL,
		key_prefix varchar(16) NOT NULL DEFAULT '',
		scopes varchar(50) NOT NULL DEFAULT 'read',
		last_used datetime DEFAULT NULL,
		created_at datetime NOT NULL,
		revoked tinyint(1) NOT NULL DEFAULT 0,
		PRIMARY KEY  (id),
		UNIQUE KEY key_hash (key_hash),
		KEY user_id (user_id)
	) {$charset};";
	dbDelta( $sql );
}
register_activation_hook( __FILE__, 'wrak_activate' );

/**
 * Hash a raw key for storage. The raw key is never stored.
 *
 * @param string $key Raw key as shown to the user.
 * @return string HMAC-SHA256 hex digest.
 */
function wrak_hash_key( $key ) {
	return hash_hmac( 'sha256', $key, wp_salt( 'auth' ) );
}

/**
 * Generate a new key, store only its hash, and return the raw key.
 *
 * The raw key is shown to the admin exactly once — it cannot be
 * recovered afterwards, only revoked and re-created.
 *
 * @param int    $user_id Owner of the key.
 * @param string $label   Human label, e.g. "Zapier sync".
 * @param array  $scopes  e.g. array( 'read' ) or array( 'read', 'write' ).
 * @return string|WP_Error Raw key on success.
 */
function wrak_create_key( $user_id, $label, $scopes ) {
	global $wpdb;
	$user = get_user_by( 'id', (int) $user_id );
	if ( ! $user ) {
		return new WP_Error( 'wrak_no_user', __( 'Unknown user.', 'wrak' ) );
	}
	$scopes = array_values( array_intersect( array_map( 'sanitize_key', (array) $scopes ), array( 'read', 'write' ) ) );
	if ( empty( $scopes ) ) {
		$scopes = array( 'read' );
	}
	// 'write' implies 'read'.
	if ( in_array( 'write', $scopes, true ) && ! in_array( 'read', $scopes, true ) ) {
		$scopes[] = 'read';
	}

	$key = WRAK_KEY_PREFIX . bin2hex( random_bytes( 24 ) );
	$ok  = $wpdb->insert( wrak_table(), array(
		'user_id'    => $user->ID,
		'label'      => sanitize_text_field( $label ),
		'key_hash'   => wrak_hash_key( $key ),
		'key_prefix' => substr( $key, 0, 12 ),
		'scopes'     => implode( ',', $scopes ),
		'created_at' => current_time( 'mysql' ),
		'revoked'    => 0,
	) );
	if ( false === $ok ) {
		return new WP_Error( 'wrak_db_error', __( 'Could not store the API key.', 'wrak' ) );
	}
	return $key;
}

/**
 * Find a stored key row by its raw value.
 *
 * @param string $key Raw key from the request.
 * @return object|null Key row or null when unknown.
 */
function wrak_find_key( $key ) {
	global $wpdb;
	$row = $wpdb->get_row( $wpdb->prepare(
		'SELECT * FROM ' . wrak_table() . ' WHERE key_hash = %s AND revoked = 0 LIMIT 1',
		wrak_hash_key( $key )
	) );
	return $row ? $row : null;
}

/**
 * Read the API key from the request: X-API-Key header first, ?api_key= second.
 *
 * @return string Empty string when no key was supplied.
 */
function wrak_key_from_request() {
	if ( ! empty( $_SERVER['HTTP_X_API_KEY'] ) ) {
		return sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_API_KEY'] ) );
	}
	if ( function_exists( 'getallheaders' ) ) {
		$headers = getallheaders();
		if ( is_array( $headers ) ) {
			foreach ( $headers as $name => $value ) {
				if ( 'x-api-key' === strtolower( $name ) ) {
					return sanitize_text_field( $value );
				}
			}
		}
	}
	if ( ! empty( $_GET['api_key'] ) ) {
		return sanitize_text_field( wp_unslash( $_GET['api_key'] ) );
	}
	return '';
}

/**
 * Authenticate REST requests with an API key.
 *
 * Runs on rest_authentication_errors: when a key is supplied, it must be
 * valid or the request fails with 401. A valid key signs the request in as
 * its owner, so normal capability checks apply. Scope is enforced here too:
 * 'read' keys may only GET/HEAD; 'write' keys may do anything their owner
 * is allowed to do.
 *
 * @param WP_Error|bool|null $result Existing auth result.
 * @return WP_Error|bool|null
 */
function wrak_authenticate( $result ) {
	if ( true === $result || is_wp_error( $result ) || is_user_logged_in() ) {
		return $result;
	}

	$key = wrak_key_from_request();
	if ( '' === $key ) {
		return $result; // No key supplied: leave authentication to WordPress.
	}

	$row = wrak_find_key( $key );
	if ( ! $row ) {
		return new WP_Error(
			'rest_invalid_api_key',
			__( 'The supplied API key is invalid or revoked.', 'wrak' ),
			array( 'status' => 401 )
		);
	}

	$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
	$scopes = explode( ',', (string) $row->scopes );
	$is_read = in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true );
	if ( ! $is_read && ! in_array( 'write', $scopes, true ) ) {
		return new WP_Error(
			'rest_api_key_read_only',
			__( 'This API key is read-only; write requests require a write-scope key.', 'wrak' ),
			array( 'status' => 403 )
		);
	}

	// Sign in as the key owner so capability checks work normally.
	wp_set_current_user( (int) $row->user_id );

	// Record last use, at most once per 5 minutes, to avoid a write on
	// every single request. Stored in GMT so the strtotime() compare below
	// is timezone-correct.
	global $wpdb;
	$last_used = $row->last_used ? strtotime( $row->last_used . ' GMT' ) : 0;
	if ( time() - $last_used > 300 ) {
		$wpdb->update(
			wrak_table(),
			array( 'last_used' => current_time( 'mysql', true ) ),
			array( 'id' => (int) $row->id ),
			array( '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Fires after a request was authenticated with an API key.
	 *
	 * @param object $row The key row that authenticated the request.
	 */
	do_action( 'wrak_authenticated', $row );

	return true;
}
add_filter( 'rest_authentication_errors', 'wrak_authenticate', 20 );

/**
 * Register the Users → API Keys admin page.
 */
function wrak_register_page() {
	add_users_page(
		__( 'API Keys', 'wrak' ),
		__( 'API Keys', 'wrak' ),
		'manage_options',
		'wrak-api-keys',
		'wrak_render_page'
	);
}
add_action( 'admin_menu', 'wrak_register_page' );

/**
 * Handle key creation / revocation (admin-post handler).
 */
function wrak_handle_action() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to do this.', 'wrak' ) );
	}
	check_admin_referer( 'wrak_manage' );

	$base = add_query_arg( array( 'page' => 'wrak-api-keys' ), admin_url( 'users.php' ) );

	if ( isset( $_POST['wrak_create'] ) ) {
		$user_id = isset( $_POST['wrak_user_id'] ) ? (int) $_POST['wrak_user_id'] : 0;
		$label   = isset( $_POST['wrak_label'] ) ? sanitize_text_field( wp_unslash( $_POST['wrak_label'] ) ) : '';
		$scopes  = isset( $_POST['wrak_scopes'] ) && is_array( $_POST['wrak_scopes'] ) ? array_map( 'sanitize_key', $_POST['wrak_scopes'] ) : array( 'read' );
		if ( '' === $label ) {
			$label = __( 'Untitled key', 'wrak' );
		}
		$key = wrak_create_key( $user_id, $label, $scopes );
		if ( is_wp_error( $key ) ) {
			wp_safe_redirect( add_query_arg( 'wrakmsg', 'create_failed', $base ) );
			exit;
		}
		// Store the raw key in a transient so it can be shown once.
		set_transient( 'wrak_new_key_' . get_current_user_id(), $key, 60 );
		wp_safe_redirect( add_query_arg( 'wrakmsg', 'created', $base ) );
		exit;
	}

	if ( isset( $_POST['wrak_revoke'] ) && isset( $_POST['wrak_key_id'] ) ) {
		global $wpdb;
		$wpdb->update(
			wrak_table(),
			array( 'revoked' => 1 ),
			array( 'id' => (int) $_POST['wrak_key_id'] ),
			array( '%d' ),
			array( '%d' )
		);
		wp_safe_redirect( add_query_arg( 'wrakmsg', 'revoked', $base ) );
		exit;
	}

	wp_safe_redirect( $base );
	exit;
}
add_action( 'admin_post_wrak_manage', 'wrak_handle_action' );

/**
 * Render the Users → API Keys page.
 */
function wrak_render_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to view this page.', 'wrak' ) );
	}

	global $wpdb;
	$msg = isset( $_GET['wrakmsg'] ) ? sanitize_key( $_GET['wrakmsg'] ) : '';
	$new_key = '';
	if ( 'created' === $msg ) {
		$new_key = (string) get_transient( 'wrak_new_key_' . get_current_user_id() );
		delete_transient( 'wrak_new_key_' . get_current_user_id() );
	}
	$keys = $wpdb->get_results( 'SELECT * FROM ' . wrak_table() . ' ORDER BY revoked ASC, created_at DESC' );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'REST API Keys', 'wrak' ); ?></h1>

		<?php if ( 'created' === $msg && '' !== $new_key ) : ?>
			<div class="notice notice-success">
				<p><strong><?php esc_html_e( 'Key created. Copy it now — it will never be shown again.', 'wrak' ); ?></strong></p>
				<p><code style="font-size:15px;user-select:all"><?php echo esc_html( $new_key ); ?></code></p>
			</div>
		<?php elseif ( 'created' === $msg ) : ?>
			<div class="notice notice-warning"><p><?php esc_html_e( 'Key created, but the one-time display already expired. Revoke it and create a new one.', 'wrak' ); ?></p></div>
		<?php elseif ( 'create_failed' === $msg ) : ?>
			<div class="notice notice-error"><p><?php esc_html_e( 'Could not create the key. Check the user and try again.', 'wrak' ); ?></p></div>
		<?php elseif ( 'revoked' === $msg ) : ?>
			<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Key revoked. Requests using it now get a 401.', 'wrak' ); ?></p></div>
		<?php endif; ?>

		<h2><?php esc_html_e( 'Create a key', 'wrak' ); ?></h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wrak_manage' ); ?>
			<input type="hidden" name="action" value="wrak_manage">
			<table class="form-table">
				<tr>
					<th scope="row"><label for="wrak_label"><?php esc_html_e( 'Label', 'wrak' ); ?></label></th>
					<td><input type="text" id="wrak_label" name="wrak_label" class="regular-text" placeholder="<?php esc_attr_e( 'e.g. Zapier sync', 'wrak' ); ?>" required></td>
				</tr>
				<tr>
					<th scope="row"><label for="wrak_user_id"><?php esc_html_e( 'Act as user', 'wrak' ); ?></label></th>
					<td>
						<?php
						wp_dropdown_users( array(
							'name'     => 'wrak_user_id',
							'id'       => 'wrak_user_id',
							'selected' => get_current_user_id(),
							'role__in' => array( 'administrator', 'editor', 'author' ),
						) );
						?>
						<p class="description"><?php esc_html_e( 'Requests authenticate as this user, so they can only do what this user can do.', 'wrak' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Scopes', 'wrak' ); ?></th>
					<td>
						<label style="display:block"><input type="checkbox" name="wrak_scopes[]" value="read" checked> <?php esc_html_e( 'Read — GET requests', 'wrak' ); ?></label>
						<label style="display:block"><input type="checkbox" name="wrak_scopes[]" value="write"> <?php esc_html_e( 'Write — POST, PUT, PATCH, DELETE (implies read)', 'wrak' ); ?></label>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Create Key', 'wrak' ), 'primary', 'wrak_create' ); ?>
		</form>

		<h2><?php esc_html_e( 'Existing keys', 'wrak' ); ?></h2>
		<?php if ( empty( $keys ) ) : ?>
			<p><?php esc_html_e( 'No API keys yet.', 'wrak' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Label', 'wrak' ); ?></th>
						<th><?php esc_html_e( 'User', 'wrak' ); ?></th>
						<th><?php esc_html_e( 'Prefix', 'wrak' ); ?></th>
						<th><?php esc_html_e( 'Scopes', 'wrak' ); ?></th>
						<th><?php esc_html_e( 'Created', 'wrak' ); ?></th>
						<th><?php esc_html_e( 'Last used', 'wrak' ); ?></th>
						<th><?php esc_html_e( 'Status', 'wrak' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $keys as $row ) :
						$user = get_user_by( 'id', (int) $row->user_id );
						?>
						<tr>
							<td><?php echo esc_html( $row->label ); ?></td>
							<td><?php echo $user ? esc_html( $user->user_login ) : esc_html__( '(deleted user)', 'wrak' ); ?></td>
							<td><code><?php echo esc_html( $row->key_prefix ); ?>…</code></td>
							<td><?php echo esc_html( $row->scopes ); ?></td>
							<td><?php echo esc_html( mysql2date( get_option( 'date_format' ), $row->created_at ) ); ?></td>
							<td><?php echo $row->last_used ? esc_html( mysql2date( get_option( 'date_format' ), $row->last_used, true ) ) : '—'; ?></td>
							<td><?php echo $row->revoked ? esc_html__( 'Revoked', 'wrak' ) : esc_html__( 'Active', 'wrak' ); ?></td>
							<td>
								<?php if ( ! $row->revoked ) : ?>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
										<?php wp_nonce_field( 'wrak_manage' ); ?>
										<input type="hidden" name="action" value="wrak_manage">
										<input type="hidden" name="wrak_key_id" value="<?php echo esc_attr( $row->id ); ?>">
										<?php submit_button( __( 'Revoke', 'wrak' ), 'small', 'wrak_revoke', false ); ?>
									</form>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

		<h2><?php esc_html_e( 'Using a key', 'wrak' ); ?></h2>
		<p><?php esc_html_e( 'Send the key as an X-API-Key header, or as ?api_key= in the URL:', 'wrak' ); ?></p>
		<pre>curl -H "X-API-Key: rak_..." <?php echo esc_url( rest_url( 'wp/v2/posts' ) ); ?>
curl "<?php echo esc_url( rest_url( 'wp/v2/posts' ) ); ?>?api_key=rak_..."</pre>
	</div>
	<?php
}
