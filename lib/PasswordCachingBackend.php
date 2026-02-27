<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2021 Robin Appelman <robin@icewind.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\SecuritySoftening;

use OCP\ICacheFactory;
use OCP\IMemcache;
use OCP\User\Backend\ICheckPasswordBackend;
use OCP\User\Backend\ICountUsersBackend;
use OCP\User\Backend\ICreateUserBackend;
use OCP\User\Backend\IGetDisplayNameBackend;
use OCP\User\Backend\IGetHomeBackend;
use OCP\User\Backend\IGetRealUIDBackend;
use OCP\User\Backend\IPasswordHashBackend;
use OCP\User\Backend\ISetDisplayNameBackend;
use OCP\User\Backend\ISetPasswordBackend;
use OCP\UserInterface;

class PasswordCachingBackend implements UserInterface,

	ICreateUserBackend,
	ISetPasswordBackend,
	ISetDisplayNameBackend,
	IGetDisplayNameBackend,
	ICheckPasswordBackend,
	IGetHomeBackend,
	ICountUsersBackend,
	IGetRealUIDBackend,
	IPasswordHashBackend {
	private UserInterface $inner;
	private IMemcache $cache;

	public function __construct(UserInterface $inner, ICacheFactory $cacheFactory) {
		$this->cache = $cacheFactory->createLocal('security_softening');
		$this->inner = $inner;
	}

	public function implementsActions($actions) {
		return $this->inner->implementsActions($actions);
	}

	public function deleteUser($uid) {
		$this->cache->clear("$uid::");
		return $this->inner->deleteUser($uid);
	}

	public function getUsers($search = '', $limit = null, $offset = null) {
		return $this->inner->getUsers($search, $limit, $offset);
	}

	public function userExists($uid) {
		return $this->inner->userExists($uid);
	}

	public function getDisplayName($uid): string {
		return $this->inner->getDisplayName($uid);
	}

	public function getDisplayNames($search = '', $limit = null, $offset = null) {
		return $this->inner->getDisplayNames($search, $limit, $offset);
	}

	public function hasUserListings() {
		return $this->inner->hasUserListings();
	}

	public function checkPassword(string $loginName, string $password) {
		if (!$this->inner->userExists($loginName)) {
			return false;
		}
		$key = "$loginName::$password";
		$cached = $this->cache->get($key);
		if ($cached) {
			return $cached;
		}
		$result = $this->inner->checkPassword($loginName, $password);
		if ($result) {
			$this->cache->set($key, $result);
		}
		return $result;
	}

	public function countUsers() {
		return $this->inner->countUsers();
	}

	public function createUser(string $uid, string $password): bool {
		$this->cache->clear("$uid::");
		return $this->inner->createUser($uid, $password);
	}

	public function getHome(string $uid) {
		return $this->inner->getHome($uid);
	}

	public function getRealUID(string $uid): string {
		return $this->inner->getRealUID($uid);
	}

	public function setDisplayName(string $uid, string $displayName): bool {
		return $this->inner->setDisplayName($uid, $displayName);
	}

	public function setPassword(string $uid, string $password): bool {
		$this->cache->clear("$uid::");
		return $this->inner->setPassword($uid, $password);
	}

	public function getPasswordHash(string $userId): ?string {
		if ($this->inner instanceof IPasswordHashBackend) {
			return $this->inner->getPasswordHash($userId);
		} else {
			return null;
		}
	}

	public function setPasswordHash(string $userId, string $passwordHash): bool {
		$this->cache->clear("$userId::");
		if ($this->inner instanceof IPasswordHashBackend) {
			return $this->inner->setPasswordHash($userId, $passwordHash);
		} else {
			return false;
		}
	}
}
