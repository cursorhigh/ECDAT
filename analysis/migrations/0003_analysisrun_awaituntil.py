from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0002_analysisrun_session_assetassessment_session"),
    ]

    operations = [
        migrations.AlterField(
            model_name="analysisrun",
            name="status",
            field=models.CharField(
                choices=[
                    ("awaiting_context", "Awaiting context"),
                    ("queued", "Queued"),
                    ("running", "Running"),
                    ("completed", "Completed"),
                    ("failed", "Failed"),
                ],
                default="queued",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="analysisrun",
            name="await_until",
            field=models.DateTimeField(
                blank=True,
                help_text=(
                    "Deadline for the awaiting-context auto-analysis prompt "
                    "(default context fires after it)."
                ),
                null=True,
            ),
        ),
    ]