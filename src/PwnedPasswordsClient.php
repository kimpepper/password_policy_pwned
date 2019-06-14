<?php

namespace Drupal\password_policy_pwned;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

/**
 * The Pwned Passwords client.
 */
class PwnedPasswordsClient implements PwnedPasswordsClientInterface {

  /**
   * The http client.
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected $httpClient;

  /**
   * PwnedPasswordsClient constructor.
   *
   * @param \GuzzleHttp\ClientInterface $http_client
   *   The HTTP client.
   */
  public function __construct(ClientInterface $http_client) {
    $this->httpClient = $http_client;
  }

  /**
   * {@inheritdoc}
   */
  public function getOccurences($password) {
    $hash = strtoupper(sha1($password));
    $hashPrefix = substr($hash, 0, 5);
    $hashSuffix = substr($hash, 5);

    $url = "https://api.pwnedpasswords.com/range/$hashPrefix";

    try {
      $response = $this->httpClient->request('GET', $url, [
        'timeout' => 10.0,
      ]);

      if ($response->getStatusCode() == 200) {
        $body = (string) $response->getBody();
        $lines = explode("\r\n", $body);
        foreach ($lines as $line) {
          list($exposedHashSuffix, $occurrences) = explode(':', $line);
          if ($hashSuffix == $exposedHashSuffix) {
            return $occurrences;
          }
        }
      }
    }
    catch (GuzzleException $e) {
      watchdog_exception('password_policy_exposed', $e);
    }

    return 0;

  }

}
