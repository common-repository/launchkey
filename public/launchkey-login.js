/**
 * Copyright (C) 2015 LaunchKey, Inc.
 *
 * For the full copyright and license information, please view the LICENSE.txt
 * file that was distributed with this source code.
 *
 * @author Adam Englander <adam@launchkey.com>
 */

// For the login page
(function ($) {
    // Hide Password field toggle
    var $passwordField  = $('[for="user_pass"]'),
        $passwordParent = $passwordField.parent(),
        $passwordToggle = $('#lk-pass-toggle');
    $passwordField.detach();
    $passwordToggle.on('click', function(e){
        e.preventDefault();
        $passwordField.appendTo($passwordParent);
        $('#user_pass').focus()
        $(this).hide();
    });

    // Login launchkey submit
    $('#loginform').on('submit', function (e) {
        e.preventDefault();
        $(this).find('#wp-submit').prop('disabled', true);
        $('.launchkey-login-progress-bar').addClass('launchkey-active');
        // Safari fix
        setTimeout(function(){
            $('#loginform').unbind('submit').submit();
            return true;
        }, 800);
    });
}(jQuery));
