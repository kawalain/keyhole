{% from 'OPNsense/Macros/interface.macro' import physical_interface %}
{% if not helpers.empty('OPNsense.Keyhole.general.enabled') and not helpers.empty('OPNsense.Keyhole.general.upstream') %}
{%   set upstream = OPNsense.Keyhole.general.upstream %}
keyhole_enable="YES"
keyhole_options="--lan {{ physical_interface(OPNsense.Keyhole.general.interface) }} --upstream {{ upstream if ':' in upstream else upstream ~ ':53' }}"
{% else %}
keyhole_enable="NO"
{% endif %}
