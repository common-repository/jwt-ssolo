=== Plugin Name ===
Contributors: @marcofrl1 
Donate link: 
Tags: login, dgpr, authentication, secure login, jwt, token
Requires at least: 4.6
Tested up to: 5.4
Stable tag: 1.5.2
Requires PHP: 5.2.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Plugin to authenticate users through the AUTH service of SSOLO ltd

== Description ==

JWTlogin allows WordPress to use a remote user authentication system based on JWT (Json Web Token) and one time cryptographic key.
Through this plugin it will be possible to connect our WordPress installation to a GDPR (General Data Protection Regulation) compliant authentication system and with a security level at the bank level, in the basic and military version in the advanced version.
The system is compatible with any other access customization plugin and also allows for authentication of user documents (ID and proof of residence), required by current international legislation.
User data is fully encrypted and inaccessible except to the owner or manager of data management.
The plugin is completed by the possibility of creating a personalized frontend, through development kits or templates, of the pages received from the site https://auth.ssolo.co.uk.

== Installation ==

1. Register your wordpress site on https://auth.ssolo.co.uk
2. download plugin and install it on WordPress from Plugin section
3. go to the admin dashboard, you can see the item menu JWT getconfig, click on it and insert the AUTH credential received after site registration
4. You receive a servercode, you can use this code to register your users on AUTH server with the URL https://auth.ssolo.co.uk/auth/reguser.php?servercode=yourservercode
5 All done your WordPress now use a login secure server GDPR compliant.

You can download full guide to http://auth.ssolo.co.uk/auth/authapi-doc.pdf

== Frequently Asked Questions ==

= I can use jwt plugin with others login plugins ? =

Yes, JWTlogin sobstitute the default WordPress login and mantain the same access for all others plugins.

= I need to register a new user in secure mode what i need to do ? =

You must create a menu item for user registration and point it to https://auth.ssolo.co.uk/reguser.php?servercode=yourservercode

= What is the servercode and where do I find it ? =

The servercode uniquely identifies your WordPress on the authentication site.
It is sent to you when you configure the plug-in via the Get AUTH configuration menu item.

= When I register a new user, do I have to register it on AUTH and also on my site? =

No you need to register the users only on AUTH,the JWTplugin create the user on your site at the first login with the basic data profile.

= I have to manage a user but it is not possible from the WordPress admin, how should I do it? =

You need to login in AUTH with credentials used to register your site, at the left on the screen you can see the item check user.
All data management permitted to be compliant with DGPR can be done from this page.

= I have a site with many users, if install JWT login i can lost this users from my site ? =

No, the important is that you register on AUTH server the customer with the same email used on your wordpress site.
If the user exist the plugin update it to the new security level. Important is that wordpress login is permitted with the email at login name.

== Screenshots ==

authmain.png, jwt-ssoloadm1.png, jwt-ssoloadm2.png, jwt-ssoloadm3.png, jwt-ssolouser1.png,jwt-ssolousr2.png,jwt-ssolousr4.png

== Changelog ==

= 1.5.2 =
* Add security check on caller hosts

= 1.5 =
* Implementation of JWT fase 2


= 1.0 =
* Implementation secure customer verification (LYC)

== Arbitrary section ==



