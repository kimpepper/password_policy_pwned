<?php

namespace Drupal\password_policy_pwned\Plugin\PasswordConstraint;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\password_policy\PasswordConstraintBase;
use Drupal\password_policy\PasswordPolicyValidation;
use Drupal\password_policy_pwned\PwnedPasswordsClientInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Enforces that a password was not exposed through data breaches.
 *
 * @PasswordConstraint(
 *   id = "pwned_passwords",
 *   title = @Translation("Pwned Passwords"),
 *   description = @Translation("Provide restrictions on exposed passwords through Pwned Passwords."),
 *   error_message = @Translation("Your password has been exposed in a data breach."),
 * )
 */
class PasswordPnwed extends PasswordConstraintBase implements ContainerFactoryPluginInterface {

  /**
   * The Pwned Passwords service.
   *
   * @var \Drupal\password_policy_pwned\PwnedPasswordsClientInterface
   */
  protected $pwnedPasswordsClient;

  /**
   * Constructs a new PasswordExposed constraint.
   *
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param mixed $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\password_policy_pwned\PwnedPasswordsClientInterface $pwned_passwords_client
   *   The Pwned Passwords service.
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, PwnedPasswordsClientInterface $pwned_passwords_client) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
    $this->pwnedPasswordsClient = $pwned_passwords_client;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('pwned_passwords_client')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'min_occurrences' => 1,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form['min_occurrences'] = [
      '#type' => 'number',
      '#title' => $this->t('Minumum number of occurrences'),
      '#default_value' => $this->getConfiguration()['min_occurrences'],
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    if (!is_numeric($form_state->getValue('min_occurrences')) or $form_state->getValue('min_occurrences') <= 0) {
      $form_state->setErrorByName('min_occurrences', $this->t('The minimum occurrences must be a positive number.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $this->configuration['min_occurrences'] = $form_state->getValue('min_occurrences');
  }

  /**
   * {@inheritdoc}
   */
  public function validate($password, $user_context) {
    $validation = new PasswordPolicyValidation();
    if (!$password) {
      return $validation;
    }

    $occurences = $this->pwnedPasswordsClient->getOccurences($password);

    if ($occurences > 0) {
      $validation->setErrorMessage($this->t("Password has been exposed :occurences time(s) in data breaches. Choose a different password. If you\'ve used this password on other sites, change it immediately!", [':occurences' => $occurences]));
    }

    return $validation;
  }

  /**
   * {@inheritdoc}
   */
  public function getSummary() {
    return $this->t('Minimum Pwned Password occurrences: @min_occurrences', ['@min_occurrences' => $this->configuration['min_occurrences']]);
  }

}
