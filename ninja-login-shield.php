<?php
/**
 * Plugin Name: Ninja Login Shield
 * Plugin URI: https://github.com/ogichanchan/ninja-login-shield
 * Description: A unique PHP-only WordPress utility. A ninja style login plugin acting as a shield. Focused on simplicity and efficiency.
 * Version: 1.0.0
 * Author: ogichanchan
 * Author URI: https://github.com/ogichanchan
 * License: GPLv2 or later
 * Text Domain: ninja-login-shield
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Define plugin constants.
 */
if ( ! defined( 'NINJA_LOGIN_SHIELD_FILE' ) ) {
	define( 'NINJA_LOGIN_SHIELD_FILE', __FILE__ );
}

if ( ! defined( 'NINJA_LOGIN_SHIELD_SLUG' ) ) {
	define( 'NINJA_LOGIN_SHIELD_SLUG', 'ninja-login-shield' );
}

/**
 * Ninja_Login_Shield Class
 *
 * This class handles all plugin functionality, including honeypot protection
 * and custom login messages, using only PHP and inline CSS.
 */
class Ninja_Login_Shield {

	/**
	 * Holds the plugin options.
	 *
	 * @var array
	 */
	private $options;

	/**
	 * Constructor.
	 * Initializes the plugin by setting up hooks and filters.
	 */
	public function __construct() {
		$this->options = get_option( 'ninja_login_shield_options', $this->get_default_options() );

		// Register hooks for the login page to add security and custom messages.
		add_action( 'login_head', array( $this, 'output_inline_login_css' ) );
		add_action( 'login_form', array( $this, 'add_honeypot_field' ) );
		add_filter( 'authenticate', array( $this, 'check_honeypot_field' ), 10, 3 );
		add_filter( 'login_message', array( $this, 'custom_login_message' ) );
		add_filter( 'wp_login_errors', array( $this, 'custom_login_errors' ), 10, 2 );

		// Register hooks for the admin settings page.
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
	}

	/**
	 * Get default plugin options.
	 *
	 * @return array Default options.
	 */
	private function get_default_options() {
		return array(
			'enable_honeypot'          => 1, // Honeypot enabled by default.
			'honeypot_field_name'      => 'ninja_hp_field_' . wp_rand( 1000, 9999 ), // Dynamic field name for better security.
			'honeypot_field_label'     => esc_html__( 'Please leave this field empty', 'ninja-login-shield' ),
			'honeypot_error_message'   => esc_html__( 'Bot detected! Access denied.', 'ninja-login-shield' ),
			'enable_custom_login_msg'  => 0, // Custom login messages disabled by default.
			'custom_login_message'     => esc_html__( 'Welcome to our secure login portal.', 'ninja-login-shield' ),
			'custom_success_message'   => esc_html__( 'Login successful! Redirecting...', 'ninja-login-shield' ), // Currently not actively used.
			'custom_failure_message'   => esc_html__( 'Invalid credentials or access denied.', 'ninja-login-shield' ),
		);
	}

	/**
	 * Output inline CSS for the login page.
	 * This CSS visually hides the honeypot field from legitimate users.
	 */
	public function output_inline_login_css() {
		if ( ! empty( $this->options['enable_honeypot'] ) ) {
			echo '<style type="text/css">
                .ninja-hp-field-container {
                    position: absolute !important;
                    left: -9999px !important;
                    top: auto !important;
                    width: 1px !important;
                    height: 1px !important;
                    overflow: hidden !important;
                    white-space: nowrap !important;
                }
            </style>';
		}
	}

	/**
	 * Adds a hidden honeypot field to the login form HTML.
	 * This field is meant to be ignored by humans but filled by bots.
	 */
	public function add_honeypot_field() {
		if ( ! empty( $this->options['enable_honeypot'] ) ) {
			$field_name  = ! empty( $this->options['honeypot_field_name'] ) ? sanitize_key( $this->options['honeypot_field_name'] ) : 'ninja_hp_field';
			$field_label = ! empty( $this->options['honeypot_field_label'] ) ? esc_attr( $this->options['honeypot_field_label'] ) : esc_html__( 'Please leave this field empty', 'ninja-login-shield' );
			?>
			<p class="ninja-hp-field-container">
				<label for="<?php echo esc_attr( $field_name ); ?>"><?php echo esc_html( $field_label ); ?></label>
				<input type="text" name="<?php echo esc_attr( $field_name ); ?>" id="<?php echo esc_attr( $field_name ); ?>" tabindex="-1" autocomplete="off" />
			</p>
			<?php
		}
	}

	/**
	 * Checks the honeypot field during the authentication process.
	 * If the honeypot field is filled, it means a bot likely submitted the form,
	 * and authentication is denied.
	 *
	 * @param WP_User|WP_Error $user     WP_User object if authentication passed, WP_Error otherwise.
	 * @param string           $username Username or email address.
	 * @param string           $password User password.
	 * @return WP_User|WP_Error Modified user object or WP_Error.
	 */
	public function check_honeypot_field( $user, $username, $password ) {
		if ( ! empty( $this->options['enable_honeypot'] ) ) {
			$field_name = ! empty( $this->options['honeypot_field_name'] ) ? sanitize_key( $this->options['honeypot_field_name'] ) : 'ninja_hp_field';

			// Check if the honeypot field was submitted and is not empty.
			if ( isset( $_POST[ $field_name ] ) && ! empty( $_POST[ $field_name ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$error_message = ! empty( $this->options['honeypot_error_message'] ) ? $this->options['honeypot_error_message'] : esc_html__( 'Bot detected! Access denied.', 'ninja-login-shield' );
				// Return a WP_Error to indicate failed authentication due to bot detection.
				return new WP_Error( 'ninja_honeypot_error', '<strong>' . esc_html__( 'ERROR', 'ninja-login-shield' ) . ':</strong> ' . esc_html( $error_message ) );
			}
		}
		return $user; // Return the original user object if honeypot check passes or is disabled.
	}

	/**
	 * Filters the message displayed on the login page.
	 * Allows for a custom general login message.
	 *
	 * @param string $message The current login message HTML.
	 * @return string Modified login message HTML.
	 */
	public function custom_login_message( $message ) {
		if ( ! empty( $this->options['enable_custom_login_msg'] ) && ! empty( $this->options['custom_login_message'] ) ) {
			// Wrap the custom message in a paragraph with class 'message' for consistent styling.
			$message = '<p class="message">' . esc_html( $this->options['custom_login_message'] ) . '</p>';
		}
		return $message;
	}

	/**
	 * Filters the login error messages displayed on the login page.
	 * Replaces specific standard login failure messages with a custom one.
	 *
	 * @param WP_Error $errors   WP_Error object containing current login errors.
	 * @param string   $redirect Redirect URL (not directly used here but part of the filter signature).
	 * @return WP_Error Modified WP_Error object.
	 */
	public function custom_login_errors( $errors, $redirect ) {
		if ( ! empty( $this->options['custom_failure_message'] ) ) {
			$error_codes_to_override = array( 'incorrect_password', 'invalid_username', 'ninja_honeypot_error' );
			$modified                = false;

			// Check if any of the target error codes are present and remove them.
			foreach ( $error_codes_to_override as $code ) {
				if ( $errors->has_error( $code ) ) {
					$errors->remove( $code );
					$modified = true;
				}
			}

			// If any relevant errors were present, or if there's a generic 'login_failed' error, add the custom message.
			if ( $modified || ( $errors->get_error_codes() === array( 'login_failed' ) && $errors->get_error_data('login_failed') === null ) ) {
				$errors->add( 'ninja_login_failure', '<strong>' . esc_html__( 'ERROR', 'ninja-login-shield' ) . ':</strong> ' . esc_html( $this->options['custom_failure_message'] ) );
			}
		}
		return $errors;
	}

	/**
	 * Adds the plugin settings page to the WordPress admin "Settings" menu.
	 */
	public function add_admin_menu() {
		add_options_page(
			esc_html__( 'Ninja Login Shield Settings', 'ninja-login-shield' ), // Page title.
			esc_html__( 'Login Shield', 'ninja-login-shield' ), // Menu title.
			'manage_options',                                   // Capability required to access.
			NINJA_LOGIN_SHIELD_SLUG,                            // Menu slug.
			array( $this, 'settings_page_callback' )            // Callback function to render page.
		);
	}

	/**
	 * Renders the HTML for the plugin's settings page in the admin area.
	 */
	public function settings_page_callback() {
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Ninja Login Shield Settings', 'ninja-login-shield' ); ?></h1>
			<form method="post" action="options.php">
				<?php
				// Output security fields for the registered setting.
				settings_fields( 'ninja_login_shield_options_group' );
				// Output settings sections and fields.
				do_settings_sections( NINJA_LOGIN_SHIELD_SLUG );
				// Output save button.
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Registers all plugin settings, sections, and fields with WordPress.
	 */
	public function register_settings() {
		// Register the main option group.
		register_setting(
			'ninja_login_shield_options_group', // Option group.
			'ninja_login_shield_options',       // Option name (will be stored as a single array).
			array( $this, 'sanitize_options' )  // Sanitize callback for all options.
		);

		// Add Honeypot Shield settings section.
		add_settings_section(
			'ninja_login_shield_honeypot_section', // ID for the section.
			esc_html__( 'Honeypot Shield Settings', 'ninja-login-shield' ), // Title of the section.
			array( $this, 'honeypot_section_callback' ), // Callback to render section description.
			NINJA_LOGIN_SHIELD_SLUG                     // Page slug this section belongs to.
		);

		// Add individual fields for Honeypot Shield.
		add_settings_field(
			'enable_honeypot',
			esc_html__( 'Enable Honeypot', 'ninja-login-shield' ),
			array( $this, 'enable_honeypot_callback' ),
			NINJA_LOGIN_SHIELD_SLUG,
			'ninja_login_shield_honeypot_section'
		);

		add_settings_field(
			'honeypot_field_name',
			esc_html__( 'Honeypot Field Name', 'ninja-login-shield' ),
			array( $this, 'honeypot_field_name_callback' ),
			NINJA_LOGIN_SHIELD_SLUG,
			'ninja_login_shield_honeypot_section'
		);

		add_settings_field(
			'honeypot_field_label',
			esc_html__( 'Honeypot Field Label', 'ninja-login-shield' ),
			array( $this, 'honeypot_field_label_callback' ),
			NINJA_LOGIN_SHIELD_SLUG,
			'ninja_login_shield_honeypot_section'
		);

		add_settings_field(
			'honeypot_error_message',
			esc_html__( 'Honeypot Error Message', 'ninja-login-shield' ),
			array( $this, 'honeypot_error_message_callback' ),
			NINJA_LOGIN_SHIELD_SLUG,
			'ninja_login_shield_honeypot_section'
		);

		// Add Custom Login Messages settings section.
		add_settings_section(
			'ninja_login_shield_messages_section', // ID.
			esc_html__( 'Custom Login Messages', 'ninja-login-shield' ), // Title.
			array( $this, 'messages_section_callback' ), // Callback.
			NINJA_LOGIN_SHIELD_SLUG                     // Page.
		);

		// Add individual fields for Custom Login Messages.
		add_settings_field(
			'enable_custom_login_msg',
			esc_html__( 'Enable Custom Login Message', 'ninja-login-shield' ),
			array( $this, 'enable_custom_login_msg_callback' ),
			NINJA_LOGIN_SHIELD_SLUG,
			'ninja_login_shield_messages_section'
		);

		add_settings_field(
			'custom_login_message',
			esc_html__( 'General Login Message', 'ninja-login-shield' ),
			array( $this, 'custom_login_message_callback' ),
			NINJA_LOGIN_SHIELD_SLUG,
			'ninja_login_shield_messages_section'
		);

		// Note: 'custom_success_message' is not actively displayed by this version of the plugin,
		// but the option field is available for future expansion or custom use.
		add_settings_field(
			'custom_failure_message',
			esc_html__( 'Failed Login Message', 'ninja-login-shield' ),
			array( $this, 'custom_failure_message_callback' ),
			NINJA_LOGIN_SHIELD_SLUG,
			'ninja_login_shield_messages_section'
		);
	}

	/**
	 * Sanitizes the plugin options array before saving to the database.
	 *
	 * @param array $input The raw input array from the settings form.
	 * @return array The sanitized options array.
	 */
	public function sanitize_options( $input ) {
		$new_input = $this->options; // Start with current options to preserve unset values.

		// Sanitize Honeypot settings.
		$new_input['enable_honeypot']        = isset( $input['enable_honeypot'] ) ? (bool) $input['enable_honeypot'] : false;
		$new_input['honeypot_field_name']    = isset( $input['honeypot_field_name'] ) ? sanitize_key( $input['honeypot_field_name'] ) : '';
		// Ensure honeypot field name always has a value, regenerate if empty.
		if ( empty( $new_input['honeypot_field_name'] ) ) {
			$new_input['honeypot_field_name'] = 'ninja_hp_field_' . wp_rand( 1000, 9999 );
		}
		$new_input['honeypot_field_label']   = isset( $input['honeypot_field_label'] ) ? sanitize_text_field( $input['honeypot_field_label'] ) : '';
		$new_input['honeypot_error_message'] = isset( $input['honeypot_error_message'] ) ? sanitize_text_field( $input['honeypot_error_message'] ) : '';

		// Sanitize Custom Login Messages settings.
		$new_input['enable_custom_login_msg'] = isset( $input['enable_custom_login_msg'] ) ? (bool) $input['enable_custom_login_msg'] : false;
		$new_input['custom_login_message']    = isset( $input['custom_login_message'] ) ? sanitize_text_field( $input['custom_login_message'] ) : '';
		$new_input['custom_success_message']  = isset( $input['custom_success_message'] ) ? sanitize_text_field( $input['custom_success_message'] ) : ''; // Not actively used but sanitized.
		$new_input['custom_failure_message']  = isset( $input['custom_failure_message'] ) ? sanitize_text_field( $input['custom_failure_message'] ) : '';

		return $new_input;
	}

	/**
	 * Callback for the Honeypot settings section. Outputs introductory text.
	 */
	public function honeypot_section_callback() {
		esc_html_e( 'Configure the honeypot field to detect and block bots attempting to log in.', 'ninja-login-shield' );
	}

	/**
	 * Callback for the 'enable_honeypot' settings field. Renders a checkbox.
	 */
	public function enable_honeypot_callback() {
		?>
		<label>
			<input type="checkbox" name="ninja_login_shield_options[enable_honeypot]" value="1" <?php checked( 1, $this->options['enable_honeypot'], true ); ?> />
			<?php esc_html_e( 'Check to enable the honeypot protection.', 'ninja-login-shield' ); ?>
		</label>
		<?php
	}

	/**
	 * Callback for the 'honeypot_field_name' settings field. Renders a text input.
	 */
	public function honeypot_field_name_callback() {
		?>
		<input type="text" name="ninja_login_shield_options[honeypot_field_name]" value="<?php echo esc_attr( $this->options['honeypot_field_name'] ); ?>" class="regular-text" />
		<p class="description"><?php esc_html_e( 'The HTML "name" attribute for the honeypot field. Change this periodically to make it harder for bots. Must be unique.', 'ninja-login-shield' ); ?></p>
		<?php
	}

	/**
	 * Callback for the 'honeypot_field_label' settings field. Renders a text input.
	 */
	public function honeypot_field_label_callback() {
		?>
		<input type="text" name="ninja_login_shield_options[honeypot_field_label]" value="<?php echo esc_attr( $this->options['honeypot_field_label'] ); ?>" class="regular-text" />
		<p class="description"><?php esc_html_e( 'The accessibility label for the hidden honeypot field. Keep it descriptive for screen readers.', 'ninja-login-shield' ); ?></p>
		<?php
	}

	/**
	 * Callback for the 'honeypot_error_message' settings field. Renders a text input.
	 */
	public function honeypot_error_message_callback() {
		?>
		<input type="text" name="ninja_login_shield_options[honeypot_error_message]" value="<?php echo esc_attr( $this->options['honeypot_error_message'] ); ?>" class="regular-text" />
		<p class="description"><?php esc_html_e( 'Message displayed when a bot is detected by the honeypot.', 'ninja-login-shield' ); ?></p>
		<?php
	}

	/**
	 * Callback for the Custom Login Messages section. Outputs introductory text.
	 */
	public function messages_section_callback() {
		esc_html_e( 'Customize the messages displayed on the WordPress login screen.', 'ninja-login-shield' );
	}

	/**
	 * Callback for the 'enable_custom_login_msg' settings field. Renders a checkbox.
	 */
	public function enable_custom_login_msg_callback() {
		?>
		<label>
			<input type="checkbox" name="ninja_login_shield_options[enable_custom_login_msg]" value="1" <?php checked( 1, $this->options['enable_custom_login_msg'], true ); ?> />
			<?php esc_html_e( 'Check to enable custom login messages.', 'ninja-login-shield' ); ?>
		</label>
		<?php
	}

	/**
	 * Callback for the 'custom_login_message' settings field. Renders a text input.
	 */
	public function custom_login_message_callback() {
		?>
		<input type="text" name="ninja_login_shield_options[custom_login_message]" value="<?php echo esc_attr( $this->options['custom_login_message'] ); ?>" class="large-text" />
		<p class="description"><?php esc_html_e( 'This message appears above the login form. Leave empty for no message if not enabled.', 'ninja-login-shield' ); ?></p>
		<?php
	}

	/**
	 * Callback for the 'custom_failure_message' settings field. Renders a text input.
	 */
	public function custom_failure_message_callback() {
		?>
		<input type="text" name="ninja_login_shield_options[custom_failure_message]" value="<?php echo esc_attr( $this->options['custom_failure_message'] ); ?>" class="large-text" />
		<p class="description"><?php esc_html_e( 'This message replaces standard login failure errors (e.g., incorrect password).', 'ninja-login-shield' ); ?></p>
		<?php
	}

	/**
	 * Static method to run on plugin activation.
	 * Sets default plugin options if they do not already exist.
	 */
	public static function activate() {
		// Only set defaults if the option doesn't exist yet (first activation).
		if ( false === get_option( 'ninja_login_shield_options' ) ) {
			$instance = new self(); // Instantiate temporarily to get default options.
			add_option( 'ninja_login_shield_options', $instance->get_default_options() );
		}
	}

	/**
	 * Static method to run on plugin deactivation.
	 * Cleans up plugin options from the database.
	 */
	public static function deactivate() {
		delete_option( 'ninja_login_shield_options' );
	}
}

/**
 * Initialize the plugin.
 * Ensures the plugin runs after all other plugins are loaded.
 */
function ninja_login_shield_run() {
	new Ninja_Login_Shield();
}

// Register activation and deactivation hooks for the plugin lifecycle.
register_activation_hook( NINJA_LOGIN_SHIELD_FILE, array( 'Ninja_Login_Shield', 'activate' ) );
register_deactivation_hook( NINJA_LOGIN_SHIELD_FILE, array( 'Ninja_Login_Shield', 'deactivate' ) );

// Hook into 'plugins_loaded' to ensure all necessary WordPress functions are available.
add_action( 'plugins_loaded', 'ninja_login_shield_run' );