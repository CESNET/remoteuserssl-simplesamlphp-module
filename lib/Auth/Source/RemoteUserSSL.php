<?php

namespace SimpleSAML\Module\remoteuserssl\Auth\Source;

use SimpleSAML\Module\ldap\ConfigHelper;
use SimpleSAML\Auth\Source;
use SimpleSAML\Configuration;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Error\ErrorCodes;
use SimpleSAML\Logger;

/**
 * Getting user's identity either from REMOTE_USER or SSL_CLIENT_S_DN. The code of the module has been inspired
 * by module authX509 from Emmanuel Dreyfus <manu@netbsd.org>.
 *
 * @author Michal Prochazka, <michalp@ics.muni.cz>
 *
 * @package SimpleSAMLphp
 */
class RemoteUserSSL extends \SimpleSAML\Auth\Source
{

    /**
     * LDAPConfigHelper object
     */
    private $ldapcf;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config Configuration.
     */
    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->ldapcf = new ConfigHelper(
            $config,
            'Authentication source ' . var_export($this->authId, true)
        );

        return;
    }

    /**
     * Get REMOTE_USER or SSL_CLIENT_S_DN
     *
     * This function just gets value from REMOTE_USER and if it is empty it tries SSL_CLIENT_S_DN. If any of two is
     * filled, then it let user in.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert(is_array($state));

        $login = null;
        if (isset($_SERVER['SSL_CLIENT_S_DN'])) {
            $login = $_SERVER['SSL_CLIENT_S_DN'];
        } elseif (isset($_SERVER['REMOTE_USER'])) {
            $login = preg_replace('/^([^@]*).*/', '\1', $_SERVER['REMOTE_USER']);
        } else {
            // Both variables were empty, this shouldn't happen if the web server is properly configured
            Logger::error(
                'remoteUserSSL: user entered protected area without being properly authenticated'
            );
            $state['remoteUserSSL.error'] = "AUTHERROR";
            $this->authFailed($state);

            assert(false); // should never be reached
            return;
        }

        $dn = $this->ldapcf->searchfordn(null, $login, true);
        if ($dn === null) {
            Logger::warning('remoteuserssl: no matching user found in LDAP for login=' . $login);
            $this->authFailed($state);

            assert(false); // should never be reached
            return;
        }

        Logger::info('remoteuserssl: ' . $dn);
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
    public function authSuccesful(&$state)
    {
        Source::completeAuth($state);

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
    public function authFailed(&$state)
    {
        $config = Configuration::getInstance();

        $t = new Template($config, 'remoteuserssl:RemoteUserSSLerror.php');
        $t->data['loginurl'] = HTTP::getSelfURL();
        if (isset($state['remoteUserSSL.error'])) {
            $t->data['errorcode'] = $state['remoteUserSSL.error'];
        }
        $t->data['errorcodes'] = ErrorCodes::getAllErrorCodeMessages();

        $t->show();

        exit();
    }
}
