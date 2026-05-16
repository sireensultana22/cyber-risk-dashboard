def generate_alerts(result):

    alerts = []

    if result["risk_level"] == "HIGH":

        alerts.append(
            "Critical cyber risk detected"
        )

    if result["risk_score"] < 50:

        alerts.append(
            "Immediate action required"
        )

    for issue in result["issues_found"]:

        alerts.append(issue)

    return alerts