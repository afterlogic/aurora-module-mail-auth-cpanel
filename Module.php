<?php
/**
 * @copyright Copyright (c) 2017, Afterlogic Corp.
 * @license AGPL-3.0 or AfterLogic Software License
 *
 * This code is licensed under AGPLv3 license or AfterLogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\MailAuthCpanel;

/**
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
	 * Initializes MailAuthCpanel Module.
	 * 
	 * @ignore
	 */
	public function init() 
	{
		$oMailModule = \Aurora\System\Api::getModule('Mail');

		$this->oApiAccountsManager = $oMailModule->oApiAccountsManager;
		$this->oApiServersManager = $oMailModule->oApiServersManager;
		$this->oApiMailManager = $oMailModule->oApiMailManager;
	
		\MailSo\Config::$PreferStartTlsIfAutoDetect = !!$this->getConfig('PreferStarttls', true);
	}
	
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
		if (!is_array($aLoginParts) || $aLoginParts[0] == '')
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
		}
		$aArgs['Email'] = $aLoginParts[0];
		$oAccount = $this->oApiAccountsManager->getAccountUsedToAuthorize($aArgs['Email']);

		$bNewAccount = false;
		$bAutocreateMailAccountOnNewUserFirstLogin = \Aurora\Modules\Mail\Module::Decorator()->getConfig('AutocreateMailAccountOnNewUserFirstLogin', false);

		if ($bAutocreateMailAccountOnNewUserFirstLogin && !$oAccount)
		{
			$sEmail = $aArgs['Email'];
			$sDomain = \MailSo\Base\Utils::GetDomainFromEmail($sEmail);
			$oServer = $this->oApiServersManager->GetServerByDomain(strtolower($sDomain));
			if (!$oServer)
			{
				$oServer = $this->oApiServersManager->GetServerByDomain('*');
			}
			if ($oServer)
			{
				$oAccount = \Aurora\System\EAV\Entity::createInstance(\Aurora\System\Api::GetModule('Mail')->getNamespace() . '\Classes\Account', $this->GetName());
				$oAccount->Email = $aArgs['Email'];
				$oAccount->IncomingLogin = $aArgs['Login'];
				$oAccount->IncomingPassword = $aArgs['Password'];
				$oAccount->ServerId = $oServer->EntityId;
				$bNewAccount = true;
			}
		}

		if ($oAccount instanceof \Aurora\Modules\Mail\Classes\Account)
		{
			try
			{
				if ($bAutocreateMailAccountOnNewUserFirstLogin || !$bNewAccount)
				{
					$bNeedToUpdatePassword = $aArgs['Password'] !== $oAccount->IncomingPassword;
					$oAccount->IncomingPassword = $aArgs['Password'];

					$this->oApiMailManager->validateAccountConnection($oAccount);

					if ($bNeedToUpdatePassword)
					{
						$this->oApiAccountsManager->updateAccount($oAccount);
					}

					$bResult =  true;
				}

				if ($bAutocreateMailAccountOnNewUserFirstLogin && $bNewAccount)
				{
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
					if ($oUser instanceof \Aurora\Modules\Core\Classes\User)
					{
						$iUserId = $oUser->EntityId;
						$bPrevState = \Aurora\System\Api::skipCheckUserRole(true);
						$oAccount = \Aurora\Modules\Mail\Module::Decorator()->CreateAccount(
							$iUserId,
							$sEmail,
							$sEmail,
							$aArgs['Login'],
							$aArgs['Password'],
							array('ServerId' => $oServer->EntityId)
						);
						\Aurora\System\Api::skipCheckUserRole($bPrevState);
						if ($oAccount)
						{
							$oAccount->UseToAuthorize = true;
							$oAccount->UseThreading = $oServer->EnableThreading;
							$bResult = $this->oApiAccountsManager->updateAccount($oAccount);
						}
						else
						{
							$bResult = false;
						}
					}
				}

				if ($bResult)
				{
					$mResult = array(
						'token' => 'auth',
						'sign-me' => $aArgs['SignMe'],
						'id' => $oAccount->IdUser,
						'account' => $oAccount->EntityId,
						'account_type' => $oAccount->getName()
					);
				}
			}
			catch (\Aurora\System\Exceptions\ApiException $oException)
			{
				throw $oException;
			}
			catch (\Exception $oException) {}
		}

		return $bResult;
	}

	/**
	 * Call onLogin method, gets responses from them and returns AuthToken.
	 *
	 * @param string $Login Account login.
	 * @param string $Password Account passwors.
	 * @param string $Email Account email.
	 * @param bool $SignMe Indicates if it is necessary to remember user between sessions.
	 * @return array
	 * @throws \Aurora\System\Exceptions\ApiException
	 */
	public function Login($Login, $Password, $SignMe = false)
	{
		\Aurora\System\Api::checkUserRoleIsAtLeast(\Aurora\System\Enums\UserRole::Anonymous);

		$mResult = false;

		$aArgs = array (
			'Login' => $Login,
			'Password' => $Password,
			'SignMe' => $SignMe
		);
		$this->OnLogin(
			$aArgs,
			$mResult
		);

		if (is_array($mResult))
		{
			$iTime = $SignMe ? 0 : time() + 60 * 60 * 24 * 30;
			$sAuthToken = \Aurora\System\Api::UserSession()->Set($mResult, $iTime);

			\Aurora\System\Api::LogEvent('login-success: ' . $Login, $this->GetName());
			return array(
				'AuthToken' => $sAuthToken
			);
		}

		\Aurora\System\Api::LogEvent('login-failed: ' . $Login, $this->GetName());
		if (!is_writable(\Aurora\System\Api::DataPath()))
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::SystemNotConfigured);
		}
		throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::AuthError);
	}

}
