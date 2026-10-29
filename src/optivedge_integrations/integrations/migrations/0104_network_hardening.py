"""Network hardening - PAN-NET-001 to PAN-NET-007. Five new models, eight new columns.

NUMBERED 0104 AGAINST A HEAD OF 0100, WHICH IS DELIBERATE AND NOT A MISTAKE. This landed
in a wave of four concurrent stage 7 runs, each assigned a filename so that two could not
pick the same number, and all four declare the same dependency - the head each one found.
Four leaves in one app is a state Django refuses outright, so expect this `dependencies`
line to be rewritten when the wave is merged; the four touch different models, so the order
carries no meaning beyond the filenames they were assigned.

EVERY NEW COLUMN A CONTROL COMPARES IS NON-NULLABLE AND DEFAULTS TO ITS FIRING VALUE, and
on this domain three of those defaults are firing tokens rather than booleans:
`Interface.out_of_service_residue` defaults to `administrative_state_unknown`,
`Interface.lldp_announced_content` to `unknown_global_defaults`, and
`PanOsDhcpInterfaceConfig.dhcp_relay_state` to `relaying`. A row this migration creates and
nothing has yet renormalized therefore FIRES. That is the prescribed direction - a missing
reading reported as compliant is a customer told they are safe on the strength of nothing -
and it means the window between this migration and the first collection over-reports rather
than reporting a clean estate.

SIX COLUMNS ARE NULLABLE AND NONE OF THEM IS COMPARED BY A CONTROL. `Interface.link_state`,
`PanOsDhcpInterfaceConfig.dhcp_server_mode`, `PanOsDhcpInterfaceConfig.dhcp_relay_ipv4_enabled`,
`PanOsSessionSettings.session_rematch`, `PanOsLldpGlobalSettings.lldp_global_enable` and
`PanOsRoutingAdjacency.max_prefixes` each hold NULL because nothing has measured what the
absent key means and storing a guess would decide a control off nothing. The search layer
has no is-null operator and SQL answers every positive comparison over a NULL with no
match, so a clause written over any of these would silently select nothing - which is why
the verdict column beside each one is what a control is meant to test. Checked against the
other repo: nothing in OptivEdgeAssessments reads any of these six names today, because no
control over this domain has been built yet.

NO COLUMN IS REMOVED, RENAMED OR RE-TYPED. `Interface` is shared with the management-surface
and zone domains, and the eight columns added to it sit beside theirs.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0100_decryption_policy'),
    ]

    operations = [
        migrations.AddField(
            model_name='interface',
            name='link_state',
            field=models.CharField(blank=True, choices=[('auto', 'Auto'), ('down', 'Down'), ('up', 'Up')], max_length=8, null=True),
        ),
        migrations.AddField(
            model_name='interface',
            name='lldp_announced_content',
            field=models.CharField(choices=[('management_address', 'Management address'), ('system_description', 'System description'), ('hostname_or_role', 'Hostname or role'), ('port_and_chassis_only', 'Port and chassis only'), ('receive_only_or_off', 'Receive only, or off'), ('unknown_global_defaults', 'Unknown - global defaults')], default='unknown_global_defaults', max_length=48),
        ),
        migrations.AddField(
            model_name='interface',
            name='lldp_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='interface',
            name='lldp_node_present',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='interface',
            name='lldp_profile_name',
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name='interface',
            name='management_profile_restricts_sources',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='interface',
            name='out_of_service_residue',
            field=models.CharField(choices=[('unrestricted_management_binding', 'Management binding, no source restriction'), ('restricted_management_binding', 'Management binding, sources restricted'), ('security_zone_membership', 'Security zone membership'), ('address_only', 'Address only'), ('comment_or_link_settings_only', 'Comment or link settings only'), ('routing_instance_without_address', 'Routing instance, no address'), ('stripped_and_shut_down', 'Stripped and shut down'), ('administrative_state_unknown', 'Administrative state unknown')], default='administrative_state_unknown', max_length=48),
        ),
        migrations.AddField(
            model_name='interface',
            name='security_zone_name',
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.CreateModel(
            name='PanOsDhcpInterfaceConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('interface_name', models.CharField(max_length=64)),
                ('dhcp_server_configured', models.BooleanField(default=False)),
                ('dhcp_server_mode', models.CharField(blank=True, choices=[('enabled', 'Enabled'), ('auto', 'Auto'), ('disabled', 'Disabled')], max_length=8, null=True)),
                ('dhcp_relay_ipv4_enabled', models.BooleanField(blank=True, null=True)),
                ('dhcp_relay_state', models.CharField(choices=[('relaying', 'Relaying'), ('configured_and_off', 'Configured, every switch off'), ('not_configured', 'Not configured')], default='relaying', max_length=24)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_dhcp_interface_configs', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_dhcp_interface_configs', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_dhcp_interface_configs', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_dhcp_interface_configs', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['appliance__hostname', 'interface_name'],
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_0f4610_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance', 'interface_name'), name='integrations_unique_dhcp_interface_per_appliance')],
            },
        ),
        migrations.CreateModel(
            name='PanOsLldpGlobalSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('lldp_global_enable', models.BooleanField(blank=True, null=True)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_lldp_global_settings', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_lldp_global_settings', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_lldp_global_settings', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_lldp_global_settings', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['appliance__hostname'],
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_f7f84c_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='integrations_unique_lldp_global_per_appliance')],
            },
        ),
        migrations.CreateModel(
            name='PanOsRoutingAdjacency',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('router_name', models.CharField(max_length=64)),
                ('protocol', models.CharField(choices=[('bgp', 'BGP'), ('ospf', 'OSPFv2'), ('ospfv3', 'OSPFv3'), ('rip', 'RIP')], max_length=16)),
                ('adjacency_name', models.CharField(max_length=64)),
                ('routing_engine', models.CharField(choices=[('legacy', 'Legacy'), ('advanced', 'Advanced Routing Engine'), ('unknown', 'Unknown')], default='unknown', max_length=16)),
                ('bgp_authentication_profile', models.CharField(blank=True, max_length=64)),
                ('ospf_authentication_profile', models.CharField(blank=True, max_length=64)),
                ('authentication_profile', models.CharField(blank=True, max_length=64)),
                ('max_prefixes', models.CharField(blank=True, max_length=16, null=True)),
                ('authentication_strength', models.CharField(choices=[('none', 'None'), ('explicitly_disabled', 'Explicitly disabled'), ('weaker_inner_attachment', 'Weaker inner attachment'), ('cleartext_password', 'Cleartext password'), ('weak_digest', 'Weak digest'), ('strong_digest', 'Strong digest'), ('authenticated_and_encrypted', 'Authenticated and encrypted')], default='none', max_length=48)),
                ('prefix_limit_state', models.CharField(choices=[('no_ceiling', 'No ceiling'), ('unlimited', 'Unlimited'), ('warn_only', 'Warn only'), ('enforcing', 'Enforcing')], default='no_ceiling', max_length=16)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_routing_adjacencies', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_routing_adjacencies', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_routing_adjacencies', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_routing_adjacencies', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['appliance__hostname', 'router_name', 'protocol', 'adjacency_name'],
                'indexes': [models.Index(fields=['appliance', 'protocol'], name='integration_applian_2e16ae_idx'), models.Index(fields=['appliance', 'router_name'], name='integration_applian_bde79b_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance', 'router_name', 'protocol', 'adjacency_name'), name='integrations_unique_routing_adjacency_per_appliance')],
            },
        ),
        migrations.CreateModel(
            name='PanOsSessionSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('session_rematch', models.BooleanField(blank=True, null=True)),
                ('ipv6_firewalling', models.BooleanField(default=True)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_session_settings', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_session_settings', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_session_settings', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_session_settings', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['appliance__hostname'],
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_ffee24_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='integrations_unique_session_settings_per_appliance')],
            },
        ),
        migrations.CreateModel(
            name='PanOsTunnelInspectionCoverage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('scope', models.CharField(choices=[('vsys', 'Vsys'), ('device-group', 'Device group')], default='vsys', max_length=16)),
                ('vsys_name', models.CharField(max_length=64)),
                ('tunnel_inspect_rule_count', models.PositiveIntegerField(default=0)),
                ('tunnel_inspect_rules_collected', models.BooleanField(default=False)),
                ('tunnel_acceleration', models.BooleanField(default=True)),
                ('tunnel_inspection_coverage_state', models.CharField(choices=[('no_policy', 'No tunnel inspection policy'), ('all_rules_disabled', 'Every rule disabled'), ('protocol_subset', 'Only some tunnel protocols'), ('zone_pair_gap', 'Zone pairs not covered'), ('single_level_only', 'One level of encapsulation only'), ('overlay_id_scoped', 'Scoped to named overlay identifiers'), ('coverage_unverified_without_traffic_answer', 'Coverage unverified without a traffic answer'), ('fully_opened', 'Fully opened')], default='no_policy', max_length=48)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_tunnel_inspection_coverages', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_tunnel_inspection_coverages', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_tunnel_inspection_coverages', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pan_os_tunnel_inspection_coverages', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['appliance__hostname', 'scope', 'vsys_name'],
                'indexes': [models.Index(fields=['appliance', 'scope'], name='integration_applian_e88d23_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance', 'scope', 'vsys_name'), name='integrations_unique_tunnel_coverage_per_scope')],
            },
        ),
    ]
