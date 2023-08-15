<?php

namespace OCA\SecuritySoftening;

use OC\Security\Hasher;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IMemcache;

class CachingHasher extends Hasher {
	private IMemcache $cache;

	public function __construct(ICacheFactory $cacheFactory, IConfig $config) {
		$this->cache = $cacheFactory->createLocal('security_softening');
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
