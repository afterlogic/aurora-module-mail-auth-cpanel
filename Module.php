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
		$this->oApiAccountsManager = new \Aurora\Modules\Mail\Managers\Accounts\Manager($this);
		$this->oApiServersManager = new \Aurora\Modules\Mail\Managers\Servers\Manager($this);
		$this->oApiMailManager = new \Aurora\Modules\Mail\Managers\Main\Manager($this);
	
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
	public function onLogin($aArgs, &$mResult)
	{
		$bResult = false;
		$oServer = null;
		$aLoginParts = explode('/', $aArgs['Login']);
		if (!is_array($aLoginParts) || $aLoginParts[0] == '')
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
		}
		$aArgs['Email'] = $aLoginParts[0];
		$oAccount = $this->oApiAccountsManager->getAccountByEmail($aArgs['Email']);
		
		$bNewAccount = false;
		$bAllowNewUsersRegister = \Aurora\Modules\Mail\Module::Decorator()->getConfig('AllowNewUsersRegister', false);

		if ($bAllowNewUsersRegister && !$oAccount)
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
				$oAccount = \Aurora\System\EAV\Entity::createInstance('Aurora\Modules\Mail\Classes\Account', $this->GetName());
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
				if ($bAllowNewUsersRegister || !$bNewAccount)
				{
					$bIsUpdateNeeded = false;
					if ($oAccount->IncomingLogin !== $aArgs['Login'] || $oAccount->IncomingPassword !== $aArgs['Password'])
					{
						$bIsUpdateNeeded = true;
					}
					$oAccount->IncomingLogin = $aArgs['Login'];
					$oAccount->IncomingPassword = $aArgs['Password'];
					
					$this->oApiMailManager->validateAccountConnection($oAccount);
					
					$bResult = true;
					if ($bIsUpdateNeeded && !$bNewAccount)
					{
						$bResult = (bool) $this->oApiAccountsManager->updateAccount($oAccount);
					}
				}

				if ($bAllowNewUsersRegister && $bNewAccount)
				{
					$oAccount = \Aurora\Modules\Mail\Module::Decorator()->CreateAccount(
						0,
						$sEmail,
						$sEmail,
						$aArgs['Login'],
						$aArgs['Password'],
						array('ServerId' => $oServer->EntityId)
					);
					if ($oAccount)
					{
						$oAccount->UseToAuthorize = true;
						$bResult = $this->oApiAccountsManager->updateAccount($oAccount);
					}
					else
					{
						$bResult = false;
					}
				}

				if ($bResult)
				{
					$mResult = array(
						'token' => 'auth',
						'sign-me' => $aArgs['SignMe'],
						'id' => $oAccount->IdUser,
						'account' => $oAccount->EntityId
					);
				}
			}
			catch (\Exception $oEx) {}
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
		$this->onLogin(
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
