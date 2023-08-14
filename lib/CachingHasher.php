<?php

namespace OCA\SecuritySoftening;

use OC\Security\Hasher;
use OCP\ICache;
use OCP\IConfig;

class CachingHasher extends Hasher {
	public function __construct(private ICache $cache, IConfig $config) {
		parent::__construct($config);
	}

	public function verify(string $message, string $hash, &$newHash = null): bool {
		$key = md5("$message, $hash");
		if (!$newHash) {
			$cached = $this->cache->get($key);
			if ($cached) {
				return $cached;
			}
		}
		$result = parent::verify($message, $hash, $newHash);
		if (!$newHash) {
			$this->cache->set($key, $result);
		}
		return $result;
	}
}
