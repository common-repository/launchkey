=== LaunchKey ===
Contributors: iovation
Donate link: https://www.iovation.com/launchkey
Tags: 2 step, 2 step authentication, 2-factor, 2FA, access, access management, authentication, biometric, biometrics, decentralized, encryption, fencing, fingerprint, geofencing, identity, IAM, iPhone, LaunchKey, Launch Key, log in, login, MFA, mobile, MFA, multi-factor, multifactor, out of band, password, passwords, phishing, phone, PIN, secure, security, security policies, SSL, strong authentication, token, tokens, two step, two factor, two-factor authentication, white label, wp-admin, wp-login
Requires at least: 4.5
Tested up to: 4.7.3
Stable tag: 1.4.6
License: GPLv2 Copyright (c) 2017 iovation, Inc.
License URI: https://www.gnu.org/licenses/gpl-2.0.html

== Upgrade Notice ==

This upgrade provides the native implementation of the LaunchKey service.  The native implementation is more secure regarding secret data.  After you upgrade, your OAuth based configuration will still work as before but you will get deprecation notices as the OAuth implementation will not be supported in a future release.

== Description ==

---

_**IMPORTANT DEPRECATION ANNOUNCEMENT: On March 1, 2018, this WordPress plugin will be deprecated along with other LaunchKey SDKs, services, and resources that leverage versions v1 / v2 of the LaunchKey API. To avoid a service disruption, you must disable and uninstall your LaunchKey WordPress plugin prior to March 1. For more information, see: [<iovation.com/launchkey-legacy-deprecation>](https://www.iovation.com/launchkey-legacy-deprecation).**_

---

With [iovation LaunchKey](https://www.iovation.com/launchkey), you can remove the risk and hassle of passwords in WordPress with a login alternative that’s more secure, more capable, and easier to use than traditional passwords and 2FA tokens.

= Top features =

* Log in to WordPress without passwords. (user’s opt-in individually)
* Remotely log out of WordPress.
* More authentication options. (e.g. biometrics, geofencing, etc.)
* Hide the password field in the WP login form.
* Remove passwords from WordPress database to prevent possible theft, brute force, database injection, phishing, and other attack vectors.
* Setup security policies controlling who can log in, what level of authentication they must utilize, etc.

= How does it work? =

Instead of logging in to WordPress with a username and password, WordPress will simply push a login request to a user’s mobile device via the free LaunchKey mobile app (available on iOS, Android, and Windows Phone). Once a request is received, a user can authorize the login request inside the LaunchKey mobile app by authenticating with the security factors they’ve chosen to use, while fraudulent or accidental login requests can be easily denied.

= What types of authentication is supported? =

LaunchKey makes it easy for users to employ true multi-factor authentication (MFA) through a variety of strong authentication options on their smartphone or mobile device. Authentication options include active and passive security factors such as biometric fingerprint scan, geofencing (i.e. restricting authorization to one or more geographic locations), facial recognition, Bluetooth device factors (i.e. ensuring a Bluetooth device is within range before allowing authorization to proceed), as well as PIN codes, pattern codes, and more. 

= What happens if a device is lost or stolen? =

Lost or stolen devices can easily be remotely unpaired, rendering the mobile device useless as an authenticator. Remote unpairing is available through a simple online form or through another paired mobile device via the LaunchKey mobile app.

= How do I know the LaunchKey service is secure? =

In addition to regular security audits performed by 3rd party security researchers, LaunchKey is architected in such a manner that makes it impossible for a LaunchKey representative or anyone else to authenticate on behalf of an end user or modify a user’s response. This is possible because of LaunchKey’s unique cryptographic architecture. In fact, the LaunchKey service is 100% anonymous. All sensitive authentication data is stored locally on the user’s mobile device in secure storage and it’s inaccessible to the LaunchKey service as well as the application leveraging LaunchKey’s authentication platform (in this case, WordPress). 

= Where can I find out more information on LaunchKey? =

LaunchKey can work with any online application. For more information, visit [iovation.com](https://www.iovation.com/launchkey).

= Where can I find more information on how to use the LaunchKey mobile app? =

View the LaunchKey mobile user guide [here](https://docs.launchkey.com/user/mobile-app-guide/index.html).


== Installation ==

Full documentation: https://docs.launchkey.com/developer/cms/word-press/

= Quick Start =

1. Install and activate the LaunchKey WordPress Plugin

2. Start the configuration wizard at one of these locations:

    * Click the "Wizard" link in the LaunchKey actions menu of the Plugins List
    * Click the "Configure LaunchKey" button at the top on any Admin page
    * Go to the "LaunchKey" settings page

3. Complete the steps in the wizard

Once all of et steps in the wizard are completed, you are ready to use the LaunchKey WordPress plugin.

== Frequently Asked Questions ==

= What does this cost? =

Nothing, it's free!

= What happens to my password? =

By default, your password will still remain after you pair your LaunchKey account, but you can remove your password by clicking the "Remove WP password" link under "LaunchKey Options" within your Profile Options page in WP Admin.

= What happens if I lose my device? =

Remotely unpair your device at anytime by visiting: https://dashboard.launchkey.com/unlink

== Changelog ==
= 1.4.6 =
* Add deprecation notice

= 1.4.5 =
* Fix issue created by WP refactoring the filter/event stack in 4.7
* Simplify setup options - remove Easy Setup, SSO, White Label
* Update text to match current Dashboard language

= 1.4.4 =
* Update LaunchKey_WP_Native_Client::register_shake_error_codes to not raise warnings when the shake parameter is not an array
* Tested up to 4.6

= 1.4.3 =
* Reload the settings page on Easy Setup finish to retrieve values

= 1.4.2 =
Merge stable 1.3.1 updates into development stream
* Update remove password functionality to account for updates in WordPress 4.x
* Tested up to 4.5

= 1.4.1 =
* Fix the settings to deal with the ability to change the implementation type
* Fix context bug with SSO client in getting the login post URL
* Tested up to 4.4.2

= 1.4.0 =
* Add device based setup in Wizard

= 1.3.1 =
* Update remove password functionality to account for updates in WordPress 4.x

= 1.3.0 =
* Add network (multi-site) capability
* Add SSO create user processing for user_email, first_name, and last_name user attributes.

= 1.2.0 =
* PHP 7 compliance
* Add proper database error handling for SSO service
* Reload plugin settings page after submit to reflect changes properly
* Update to "handle" must use activation
* Add Single Log Out for SSO

= 1.1.4 =
* Fix escalation of privilege error found via bug bounty. (Ported from 1.0.6)
* Clean up CSS for small browsers with 3rd implementation type in wizard.
* Add validation for destination, audience, and time for SSO response
* Add replay attack detection to SSO
* Turn off autocomplete on standard verification in wizard to prevent important text from being obscured.
* Inform the user of their WordPress username in standard and white label wizards in case the user was migrating from SSO or OAuth and did not know or remember their WordPress username.

= 1.1.3 =
* Fix content in SSO wizard

= 1.1.2 =
* Fix typos in SSO wizard
* Fix finish redirect for SSO wizard in Safari

= 1.1.1 =
* Fix changelog versions
* Settings page show correct POST URL
* Settings page "Finish" goes to correct page

= 1.1.0 =
* Tested up to 4.3.1
* Added LaunchKey SSO integration with setup wizard
* Updated wizard and plugin page to better inform users how to pair other users' WordPress account with LaunchKey account

= 1.0.6 =
* Fix escalation of privilege error found via bug bounty.

= 1.0.5 =
* Detach and append password section of login form instead of hide and show to prevent auto-fill by browser and password managers
* Fix setup wizard verify issue for older jQuery versions in WordPress 3.x that would not complete verification

= 1.0.4 =
* Tested up to 4.3

= 1.0.3 =
* Release inconsistency change.  No actual code changed

= 1.0.2 =
* Version release fix. No actual changes to the code

= 1.0.1 =
* Cosmetic changes to configuration wizard

= 1.0.0 =
* Tested up to 4.2.2
* Split up plugin file and code
* Moved SSL Verify from constant to option
* Encrypt secret data in plug-in options
* Stopped displaying secret data in settings.  Now shows hash value.
* Add native (non-OAuth) authentication
* Add white label functionality
* Add reminders to configure plugin
* Add configuration wizard
* Update User Profile options section for better readability
* Add "Paired" column to users list

= 0.4.3 =
* Add icon to assets
* Tested up to 4.0 

= 0.4.2 =
* Update assets and readme
* Confirm support up to and including 3.9.1

= 0.4.1 =
* Our first user submitted language has been added: Chinese (WPLANG: zh_CN). Thanks @DeamworkTec! Please contact us if you would like to help translate a new language or update an existing one. 

= 0.4.0 =
* Internationalization and Localization support.
* Shortcode styling enhancements 

= 0.3.2 =
* Added shortcode (Thanks to user jaketblank!)
* Additional Output Sanitization

= 0.3.1 =
* Refresh Token support for 30 days instead of 7. Note: Default WordPress Sessions last 48 Hours.
* Updated FAQ
* WordPress 3.8 support tested and verified.

= 0.3.0 =
* 3.7 & 3.7.1 support tested and verified.
* Enhance OAuth Refresh Token support enabling longer sessions.

= 0.2.5 =
* Secure UNINSTALL added, Deactivation does not do a secure wipe and retains settings and user pairings.

= 0.2.4 =
* Added nonce to remove password and unpair links inside Profile.

= 0.2.3 =
* Verified 3.6 compatibility.

= 0.2.2 =
* Fix for issue 32bit servers had with large App Keys. 

= 0.2.1 =
* readme.txt updates. Added screenshots, FAQ and updated content.

= 0.2.0 =
* Pair/Unpair accounts within the User Profile. Allow a User to remove their password and enable LaunchKey only login.

= 0.1.3 =
* Fixed Header Issue some installations were reporting. No new features at this time.

= 0.1.2 =
* Updates based on initial user feedback.

= 0.1.1 =
* Minor updates to readme.txt  

= 0.1.0 =
* Initial Release

== Screenshots ==

1. Passwordless WP-login screen
2. Session Expire - Full integration with WordPress heartbeat enables remote session expiration with your Mobile Authenticator
3. WP Admin > Settings > LaunchKey - Not configured shows setup wizard
4. WP Admin > Settings > LaunchKey - Configuration Wizard -  Takes you step by step through the entire process
5. WP Admin > Settings > LaunchKey - Configuration Wizard - Allows you to set up the LaunchKey Mobile Authenticator or use your own authenticator with a LaunchKey White Label implementation
6. WP Admin > Settings > LaunchKey - Configuration Wizard - Walks you through verifying your configuration settings once completed
7. WP Admin > Settings > LaunchKey - Configuration Wizard - Visual verification that everything is working
8. WP Admin > Settings > LaunchKey - Configured
9. WP Admin > Users - Users list shows LaunchKey paired status of user accounts
10. WP Admin > Profile > LaunchKey Options - Unpaired
11. WP Admin > Profile > LaunchKey Options - Paired with Password
12. WP Admin > Profile > LaunchKey Options - Paired without Password
