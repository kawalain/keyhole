<script>
    $(document).ready(function () {
        mapDataToFormUI({'frm_GeneralSettings': "/api/keyhole/settings/get"}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        updateServiceControlUI('keyhole');

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                // Reject on validation errors, or the button stays busy.
                saveFormToEndpoint("/api/keyhole/settings/set", 'frm_GeneralSettings',
                    function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function () {
                updateServiceControlUI('keyhole');
            }
        });
    });
</script>

<div class="content-box">
    {{ partial('layout_partials/base_form', ['fields': general, 'id': 'frm_GeneralSettings']) }}
</div>
{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/keyhole/service/reconfigure', 'data_service_widget': 'keyhole'}) }}
