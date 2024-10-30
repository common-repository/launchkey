// For the settings/wizard page
(function ($, config) {

    var nonce = config.nonce,
        // Controls the views based on url hash
        changeView = function () {
            var view = window.location.hash.substring(1).toString();

            // Hide/show proper views
            $('[data-view]').hide();
            $('[data-view="' + view + '"]').show();

            // If a wizard view show/hide
            // wizard header using css class
            if (view.indexOf('wizard') > -1) {
                $('body').addClass('lk-wizard');
            } else {
                $('body').removeClass('lk-wizard')
            }

            // Scroll back to top
            window.scrollTo(0, 0)
        },
        showErrors = function (errors) {
            $.each(errors, function (idx, val) {
                var template = $('#lk-error-template').html();
                template = template.replace('%%%', val);
                $('.launchkey-header').append(template);
            });
            $('.notice-dismiss').on('click', function () {
                $(this).parent().remove();
            });
            window.scrollTo(0, 0)
        },
        showQrCode = function () {
            $.ajax({
                url: config.qr_code_url,
                type: 'POST',
                data: {nonce: nonce},
                success: function (data) {
                    nonce = data.nonce;
                    if (data.errors) {
                        showErrors(data.errors)
                    } else {
                        $('.lk-qr-code').each(function () {
                            this.innerHTML = ""; // Reset the QR Code
                            new QRCode(this, {
                                text: data.qr_code,
                                height: 300,
                                width: 300,
                                correctLevel: QRCode.CorrectLevel.H
                            });
                        });
                    }
                },
                error: function (data) {
                    showErrors(['Plugin Error.'])
                }
            })
        },
        handleImplementationType = function(implementation_type) {
            if (implementation_type == 'native') {
                $("#launchkey-settings-sso").hide();
                $('#launchkey-settings-standard').show();
                $('.lk-standard-only').show();
                $('.lk-white-label-only').hide();
            } else if (implementation_type == 'white-label') {
                $("#launchkey-settings-sso").hide();
                $('#launchkey-settings-standard').show();
                $('.lk-standard-only').hide();
                $('.lk-white-label-only').show();
            } else if (implementation_type == 'sso') {
                $('#launchkey-settings-standard').hide();
                $("#launchkey-settings-sso").show();
            } else {
                $('#launchkey-settings-standard').hide();
                $("#launchkey-settings-sso").hide();
            }
        };
    ;

    // Test to see if configured or not
    // Hide/show settings or wizard on load
    if (window.location.hash.substring(1).length > 1) {
        changeView();
    } else if (config.is_configured == '1') {
        window.location.hash = '#settings';
    } else {
        window.location.hash = '#wizard-home';
    }

    // Event listener to change view based on hash
    $(window).on('hashchange', changeView)

    // Accordion
    $('[data-accordion]').on('click', function (e) {
        e.preventDefault();
        var content = $(this).attr('data-accordion');
        $('[data-accordion-content="' + content + '"]').toggle();
        if ($(this).attr('data-accordion-hide-trigger')) {
            var hide = $(this).attr('data-accordion-hide-trigger');
            $('[data-accordion-hide="' + hide + '"]').toggle();
        }
    });

    // Submit Keys
    $('#lk-wizard-keys-form, #lk-settings-keys-form, #lk-wizard-sso-idp-form').on('submit', function (e) {
        e.preventDefault();
        var $self = $(this);
        var formData = new FormData(this);
        formData.append('nonce', nonce);
        $.ajax({
            url: config.url,
            type: 'POST',
            processData: false,
            contentType: false,
            data: formData,
            success: function (data) {
                nonce = data.nonce;
                $('.launchkey-spinner-processing').removeClass('launchkey-spinner-processing');
                if (data.errors) {
                    showErrors(data.errors)
                } else {
                    if ($self.attr('id') == 'lk-wizard-keys-form') {
                        window.location.hash = '#wizard-8';
                    } else if ($self.attr('id') == 'lk-wizard-sso-idp-form') {
                        window.location.hash = '#wizard-sso-8';
                    } else {
                        location.reload(true);
                    }
                }
            },
            error: function (data) {
                showErrors(['Plugin Error.'])
            }
        });
    });

    // Event listener for form submit triggers
    $('[data-launchkey-submit]').on('click', function (e) {
        e.preventDefault();
        $(this).find('.launchkey-spinner').addClass('launchkey-spinner-processing');
        var formID = $(this).attr('data-launchkey-submit');
        $('#' + formID + '').submit();
    });

    $('[data-launchkey-qr-code-reload]').on('click', function (e) {
        e.preventDefault();
        showQrCode();
    });

    // Implementation type handling
    handleImplementationType(config.implementation_type);
    $('#settings_form_implementation_type').val(config.implementation_type);
    $('#settings_form_implementation_type').change(function (event) {
        handleImplementationType($(event.target).val());
    });


    // Fouc
    $('.lk-fouc').removeClass('lk-fouc');


    $('.hide').hide();

}(jQuery, launchkey_wizard_config));
