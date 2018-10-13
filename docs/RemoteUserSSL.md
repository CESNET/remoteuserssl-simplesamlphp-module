How to use RemoteUserSSL module
===============================

Thanks to Emmanuel Dreyfus <manu@netbsd.org> who developed X509 module which
was used as a basic for this module.

The module is just getting result of the Basic authentication or SSL
authentication done by Apache web server. Therefore the module doesn't need to
cope with any unsuccessful states of login process. Apache will ensure that
the user is properly authenticated before he/she reach this module. Module
then just extract user identifier and pass it additional processing.

Apache configuration
--------------------



Module configuration
--------------------

The first thing you need to do is to enable the module:

    touch modules/authRemoteUserSSL/enable

Then you must add it as an authentication source. Here is an
example authsources.php entry:

    'RemoteUserSSL' => array(
        'authRemoteUserSSL:RemoteUserSSL',
        'hostname' => 'ldaps://ldap.example.net',
        'enable_tls' => false,
        'attributes' => array('cn', 'uid', 'mail', 'ou', 'sn'),
        'search.enable' => true,
        'search.attributes' => array('uid', 'userCertificate'),
        'search.base' => 'dc=example,dc=net',
    ),

The configuration is the same as for the LDAP module.
