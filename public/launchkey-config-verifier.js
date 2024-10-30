(function ($, config) {
    var ticks = 0,
        millis = 500,
        show_error = function(error_text) {
            $('#verify-processing').hide();
            var template = $('#lk-error-template').html();
            template = template.replace('%%%', error_text);
            $('.launchkey-header').append(template);
            $('.notice-dismiss').on('click', function() {
                $(this).parent().remove();
            });
            window.scrollTo(0, 0)
        },
        handle_error = function (error_code) {
            var error_text, config_error;
            switch (error_code) {
                case 10422:
                    error_text = 'Either the Secret Key is invalid for the Rocket Key or the Rocket is not a White Label Rocket.';
                    config_error = true;
                    break;
                case 40422:
                    error_text = 'The Secret Key is invalid for the Rocket Key.';
                    config_error = true;
                    break;
                case 10423:
                case 10425:
                case 40423:
                case 40425:
                    error_text = 'Invalid Rocket Key.';
                    config_error = true;
                    break;
                case 40424:
                    error_text = 'No paired devices.  Did you supply the correct LaunchKey username.';
                    break;
                case 40426:
                    error_text = 'Invalid username.';
                    break;
                case 10428:
                case 40428:
                    error_text = 'The Private Key in the configuration does not match the Public Key for the Rocket.';
                    config_error = true;
                    break;
                case 10435:
                case 40435:
                    error_text = 'The Rockey for the Rocket Key you provided is disabled.';
                    config_error = true;
                    break;
                case 40436:
                    error_text = 'Too many authorization attempts, please wait a moment and try again.';
                    break;
                case 40421:
                    error_text = 'An error occured. Make sure that you used the correct LaunchKey username.';
                    break;
                default:
                    error_text = 'A communication error occurred.  This is likely due to an issue with the plugin.';
            }
            if (config_error) {
                error_text = 'Configuration error: '+error_text+' <a href="#wizard-7">Reconfigure your keys.</a>';
            }
            show_error(error_text);
        },
        submit_auth = function (username) {
            $('#verify-processing').show();
            $.ajax({
                url: config.url,
                type: 'POST',
                data: {nonce: config.nonce, username: username},
                success: function (data) {
                    var error_text;
                    if ('object' !== typeof data) {
                        handle_error();
                    } else {
                        config.nonce = data.nonce;
                        if (data.error) {
                            handle_error(data.error);
                        } else if (data.completed) {
                            $('#verify-processing').hide();
                            $("#verify-success").show();
                            $('[data-view-link="wizard-9"]').show();
                        } else {
                            setTimeout(get_auth_status, 500)
                        }
                    }
                },
                error: handle_error
            });

        },
        get_auth_status = function (username) {
            if (60000 < (ticks * millis)) {
                $('#verify-processing').hide();
                show_error('Error: LaunchKey authentication timeout.')
            } else {
                ticks++;
                $.ajax({
                    url: config.url,
                    method: 'GET',
                    data: {nonce: config.nonce},
                    success: function (data) {
                        var error_text;
                        if ('object' !== typeof data) {
                            $('#verify-processing').hide();
                            handle_error();
                        } else {
                            config.nonce = data.nonce;
                            if (data.error) {
                                handle_error(data.error);
                            } else if (data.completed) {
                                $('#verify-processing').hide();
                                $("#verify-success").show();
                                $('[data-view-link="wizard-9"]').show();
                            } else {
                                setTimeout(get_auth_status, 500)
                            }
                        }
                    },
                    error: handle_error
                });
            }
        };
    
        // Standard
        $('#verify-native-form').submit(function (event) {
            event.preventDefault();
            var username = $('#username').val();
            if (!username) {
                show_error('Username required.')
            } else {
                submit_auth(username);
            }
        });

        // WL
        $('#lk-wl-pair').on('click', function (event) {
            event.preventDefault();
            $('#verify-processing').show();
            $.ajax({
                url: config.url,
                type: 'POST',
                data: {nonce: config.nonce, verify_action: 'pair'},
                success: function (data) {
                    $('#verify-processing').hide();
                    if ('object' !== typeof data) {
                        handle_error();
                    } else {
                        config.nonce = data.nonce;
                        if (data.error) {
                            handle_error(data.error);
                        } else {
                            $('#pairing-manual-code').html(data.manual_code);
                            $('#pairing-qr-code').attr('src', data.qrcode_url);

                            $('#lk-wl-pair-step-verify').removeClass('launchkey-hide');

                            $('#verify-white-label').on('click', function (event) {
                                event.preventDefault();
                                submit_auth(null);
                            });
                        }
                    }
                },
                error: handle_error
            });
        });

}(jQuery, launchkey_verifier_config));