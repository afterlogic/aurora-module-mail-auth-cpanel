<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\MailAuthCpanel;

use Aurora\Modules\Mail\Module as MailModule;

/**
 * This module allows cPanel user to Access Webmail from Email Accounts screen.
 *
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing Afterlogic Software License
 * @copyright Copyright (c) 2023, Afterlogic Corp.
 *
 * @property Settings $oModuleSettings
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
    protected $aRequireModules = array(
        'Mail'
    );

    public $oApiMailManager = null;
    public $oApiAccountsManager = null;
    public $oApiServersManager = null;

    /**
     * @return Module
     */
    public static function getInstance()
    {
        return parent::getInstance();
    }

    /**
     * @return Module
     */
    public static function Decorator()
    {
        return parent::Decorator();
    }

    /**
     * @return Settings
     */
    public function getModuleSettings()
    {
        return $this->oModuleSettings;
    }

    /**
     * Initializes MailAuthCpanel Module.
     *
     * @ignore
     */
    public function init() {}

    /**
     * Attempts to authorize user via mail account with specified credentials.
     *
     * @ignore
     * @param array $aArgs Credentials.
     * @param array|boolean $mResult List of results values.
     * @return boolean
     */
    protected function OnLogin($aArgs, &$mResult)
    {
        $bResult = false;
        $oServer = null;
        $iUserId = 0;

        $aLoginParts = explode('/', $aArgs['Login']);
        if (!is_array($aLoginParts) || $aLoginParts[0] == '') {
            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
        }
        $aArgs['Email'] = $aLoginParts[0];
        $oAccount = MailModule::getInstance()->getAccountsManager()->getAccountUsedToAuthorize($aArgs['Email']);

        $bNewAccount = false;
        $bAutocreateMailAccountOnNewUserFirstLogin = MailModule::getInstance()->oModuleSettings->AutocreateMailAccountOnNewUserFirstLogin;
        $sEmail = $aArgs['Email'];
        if ($bAutocreateMailAccountOnNewUserFirstLogin && !$oAccount) {
            $sDomain = \MailSo\Base\Utils::GetDomainFromEmail($sEmail);
            $oServer = MailModule::getInstance()->getServersManager()->GetServerByDomain(strtolower($sDomain));
            if (!$oServer) {
                $oServer = MailModule::getInstance()->getServersManager()->GetServerByDomain('*');
            }
            if ($oServer) {
                $oAccount = new \Aurora\Modules\Mail\Models\MailAccount();
                $oAccount->Email = $aArgs['Email'];
                $oAccount->IncomingLogin = $aArgs['Login'];
                $oAccount->setPassword($aArgs['Password']);
                $oAccount->ServerId = $oServer->Id;
                $bNewAccount = true;
            }
        }

        if ($oAccount instanceof \Aurora\Modules\Mail\Models\MailAccount) {
            try {
                if ($bAutocreateMailAccountOnNewUserFirstLogin || !$bNewAccount) {
                    $bNeedToUpdatePasswordOrLogin = $aArgs['Password'] !== $oAccount->getPassword() || $aArgs['Login'] !== $oAccount->IncomingLogin;
                    $oAccount->IncomingLogin = $aArgs['Login'];
                    $oAccount->setPassword($aArgs['Password']);

                    MailModule::getInstance()->getMailManager()->validateAccountConnection($oAccount);

                    if ($bNeedToUpdatePasswordOrLogin) {
                        MailModule::getInstance()->getAccountsManager()->updateAccount($oAccount);
                    }

                    $bResult =  true;
                }

                if ($bAutocreateMailAccountOnNewUserFirstLogin && $bNewAccount) {
                    $oUser = null;
                    $aSubArgs = array(
                        'UserName' => $sEmail,
                        'Email' => $sEmail,
                        'UserId' => $iUserId
                    );
                    $this->broadcastEvent(
                        'CreateAccount',
                        $aSubArgs,
                        $oUser
                    );
                    if ($oUser instanceof \Aurora\Modules\Core\Models\User) {
                        $iUserId = $oUser->Id;
                        $bPrevState = \Aurora\System\Api::skipCheckUserRole(true);
                        $oAccount = MailModule::Decorator()->CreateAccount(
                            $iUserId,
                            $sEmail,
                            $sEmail,
                            $aArgs['Login'],
                            $aArgs['Password'],
                            array('ServerId' => $oServer->Id)
                        );
                        \Aurora\System\Api::skipCheckUserRole($bPrevState);
                        if ($oAccount) {
                            $oAccount->UseToAuthorize = true;
                            $oAccount->UseThreading = $oServer->EnableThreading;
                            $bResult = MailModule::getInstance()->getAccountsManager()->updateAccount($oAccount);
                        } else {
                            $bResult = false;
                        }
                    }
                }

                if ($bResult) {
                    $mResult = \Aurora\System\UserSession::getTokenData($oAccount, $aArgs['SignMe']);
                }
            } catch (\Aurora\System\Exceptions\ApiException $oException) {
                throw $oException;
            } catch (\Exception $oException) {
            }
        }

        return $bResult;
    }

    /**
     * Call onLogin method, gets responses from them and returns AuthToken.
     *
     * @param string $Login Account login.
     * @param string $Password Account passwors.
     * @param bool $SignMe Indicates if it is necessary to remember user between sessions.
     * @return array
     * @throws \Aurora\System\Exceptions\ApiException
     */
    public function Login($Login, $Password, $SignMe = false)
    {
        \Aurora\System\Api::checkUserRoleIsAtLeast(\Aurora\System\Enums\UserRole::Anonymous);

        $mResult = false;

        $aArgs = array(
            'Login' => $Login,
            'Password' => $Password,
            'SignMe' => $SignMe
        );
        $this->OnLogin(
            $aArgs,
            $mResult
        );

        if (is_array($mResult)) {
            $iTime = $SignMe ? 0 : time() + 60 * 60 * 24 * 30;
            $sAuthToken = \Aurora\System\Api::UserSession()->Set($mResult, $iTime);

            \Aurora\System\Api::LogEvent('login-success: ' . $Login, self::GetName());
            return array(
                'AuthToken' => $sAuthToken
            );
        }

        \Aurora\System\Api::LogEvent('login-failed: ' . $Login, self::GetName());
        if (!is_writable(\Aurora\System\Api::DataPath())) {
            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::SystemNotConfigured);
        }
        throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::AuthError);
    }
}
