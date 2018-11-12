<?php
/**
 * Getting user's identity either from REMOTE_USER or SSL_CLIENT_S_DN. The code of the module has been inspired by module authX509 from Emmanuel Dreyfus <manu@netbsd.org>.
 *
 * @author Michal Prochazka, <michalp@ics.muni.cz>
 *
 * @package SimpleSAMLphp
 */
class sspmod_remoteuserssl_Auth_Source_RemoteUserSSL extends SimpleSAML_Auth_Source {

    /**
     * LDAPConfigHelper object
     */
    private $ldapcf;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config) {
        assert('is_array($info)');
        assert('is_array($config)');

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->ldapcf = new sspmod_ldap_ConfigHelper(
            $config,
            'Authentication source '.var_export($this->authId, true)
        );

        return;
    }

    /**
     * Get REMOTE_USER or SSL_CLIENT_S_DN
     *
     * This function just gets value from REMOTE_USER and if it is empty it tries SSL_CLIENT_S_DN. If any of two is filled, then it let user in.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state) {
	assert(is_array($state));

        $login = null;
        if (isset($_SERVER['REMOTE_USER'])) {
            $login = preg_replace('/^([^@]*).*/', '\1', $_SERVER['REMOTE_USER']);
        } elseif (isset($_SERVER['SSL_CLIENT_S_DN'])) {
            $login = $_SERVER['SSL_CLIENT_S_DN'];
        } else {
            // Both variables were empty, this shouldn't happen if the web server is properly configured
            \SimpleSAML\Logger::error('authRemoteUserSSL: user entered protected area without being properly authenticated');
            $state['authRemoteUserSSL.error'] = "AUTHERROR";
            $this->authFailed($state);

            assert(false); // should never be reached
            return;
        }

        $dn = $this->ldapcf->searchfordn(null, $login, true);
        if ($dn === null) {
            \SimpleSAML\Logger::warning('authRemoteUserSSL: no matching user found in LDAP for login='.$login);
            $state['authRemoteUserSSL.error'] = "UNKNOWNUSER";
            $this->authFailed($state);

            assert(false); // should never be reached
            return;
        }

        \SimpleSAML\Logger::info('authRemoteUserSSL: '.$dn);
	$attributes = $this->ldapcf->getAttributes($dn);
        assert(is_array($attributes));
        $state['Attributes'] = $attributes;

	$this->authSuccesful($state);

        assert(false); // should never be reached
        return;
    }

    /**
     * Finish a successful authentication.
     *
     * This function can be overloaded by a child authentication class that wish to perform some operations after login.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authSuccesful(&$state) {
        SimpleSAML_Auth_Source::completeAuth($state);

        assert(false); // should never be reached
       	return;
    }

    /**
     * Finish a failed authentication.
     *
     * This function can be overloaded by a child authentication class that wish to perform some operations on failure.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authFailed(&$state) {
        $config = \SimpleSAML\Configuration::getInstance();

        $t = new \SimpleSAML\XHTML\Template($config, 'authRemoteUserSSL:error.php');
        $t->data['loginurl'] = \SimpleSAML\Utils\HTTP::getSelfURL();
        $t->data['errorcode'] = $state['authRemoteUserSSL.error'];
        $t->data['errorcodes'] = \SimpleSAML\Error\ErrorCodes::getAllErrorCodeMessages();

        $t->show();
	
        exit();
    }
}
