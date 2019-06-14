<?php

namespace Drupal\password_policy_exposed\Tests\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Tests the password was exposed through data breaches.
 *
 * @group password_policy_exposed
 */
class PasswordExposedTests extends BrowserTestBase {

  public static $modules = ['password_policy', 'password_policy_exposed'];

  /**
   * Test history constraint.
   */
  public function testPasswordExposed() {
    // Create user with permission to create policy.
    $user1 = $this->drupalCreateUser([
      'administer site configuration',
      'administer users',
      'administer permissions',
    ]);
    $this->drupalLogin($user1);

    $user2 = $this->drupalCreateUser();

    $rid = $this->drupalCreateRole([]);

    $edit = [
      'roles[' . $rid . ']' => $rid,
      'pass[pass1]' => $user2->pass_raw,
      'pass[pass2]' => $user2->pass_raw,
    ];
    $user_path = 'user/' . $user2->id() . '/edit';
    $this->drupalPostForm($user_path, $edit, t('Save'));

    // Create new password reset policy for role.
    $this->drupalGet("admin/config/security/password-policy/add");
    $edit = [
      'id' => 'test',
      'label' => 'test',
      'password_reset' => '1',
    ];
    // Set reset and policy info.
    $this->drupalPostForm(NULL, $edit, 'Next');

    $this->assertText('No constraints have been configured.');

    // Enable hibp as exposed provider constraint for test policy.
    $edit = [
      'exposed_providers_enabled[exposed_providers_enabled_hibp]' => TRUE,
    ];
    $this->drupalPostForm('admin/config/system/password_policy/constraint/add/test/password_policy_exposed_constraint', $edit, 'Save');

    $this->assertText('password_policy_exposed_constraint');
    $this->assertText('Checks whether passwords are exposed in data breaches using: Have I Been Pwned');

    // Go to the next page.
    $this->drupalPostForm(NULL, [], 'Next');

    // Set the roles for the policy.
    $edit = [
      'roles[' . $rid . ']' => $rid,
    ];
    $this->drupalPostForm(NULL, $edit, 'Finish');

    $this->assertText('Saved the test Password Policy.');

    // Login as user2.
    $this->drupalLogin($user2);

    // Test a weak password that should fail.
    $newPasswordFail = 'pass';
    $edit = [
      'current_pass' => $user2->pass_raw,
      'pass[pass1]' => $newPasswordFail,
      'pass[pass2]' => $newPasswordFail,
    ];
    $this->drupalPostAjaxForm($user_path, $edit, 'pass[pass1]');
    $this->assertText('Fail - Password has been exposed in a data breach. Choose a different password. If you\'ve used this password on other sites, change it immediately!');
    $this->assertText('Checks whether passwords are exposed in data breaches using: Have I Been Pwned');

    // Test a strong password that should pass.
    $newPasswordPass = $this->randomString(16);
    $edit = [
      'current_pass' => $user2->pass_raw,
      'pass[pass1]' => $newPasswordPass,
      'pass[pass2]' => $newPasswordPass,
    ];
    $this->drupalPostAjaxForm($user_path, $edit, 'pass[pass1]');
    $this->assertText('Pass');
    $this->assertText('Checks whether passwords are exposed in data breaches using: Have I Been Pwned');

    $this->drupalLogout();
  }

}
