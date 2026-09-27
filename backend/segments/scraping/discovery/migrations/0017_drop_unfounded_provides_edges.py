"""Remove `provides` edges that were recorded without provisioning evidence.

`record_dependency_graph` used to link every crypto dependency to every asset in
the same project directory, including certificates, containers and binaries, with
`detail='same project'`. A `provides` edge asserts the package backs that
artefact, so those rows were unfounded claims rather than observations, and the
reasoning stage would have read them as fact.

Only the unfounded rows are removed. `depends_on` edges come from resolved lock
files, and `provides` rows with real evidence ('named in the finding', 'same
algorithm family') are left alone.
"""

from django.db import migrations

# Asset types a declared crypto library cannot plausibly provide.
UNPROVIDABLE_ASSET_TYPES = (
    "certificate",
    "binary",
    "firmware",
    "container",
    "key_reference",
    "cloud_resource",
    "infrastructure",
    "hardware",
    "network_endpoint",
    "external_service",
    "api",
)


def purge_unfounded_provides(apps, schema_editor):
    DependencyRelation = apps.get_model("discovery", "DependencyRelation")
    removed = DependencyRelation.objects.filter(
        relation_type="provides",
        to_asset__asset_type__in=UNPROVIDABLE_ASSET_TYPES,
    ).delete()[0]
    removed += DependencyRelation.objects.filter(
        relation_type="provides",
        detail="same project",
    ).delete()[0]
    return removed


class Migration(migrations.Migration):

    dependencies = [
        ("discovery", "0016_graphnode_graphedge_and_more"),
    ]

    operations = [
        migrations.RunPython(
            code=purge_unfounded_provides,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
