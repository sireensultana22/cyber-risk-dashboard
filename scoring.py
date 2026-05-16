from rules import rules


def calculate_risk(data):

    score = 100

    issues = []

    recommendations = []

    for rule in rules:

        if rule["condition"](data):

            score -= rule["risk"]

            issues.append(
                rule["message"]
            )

            recommendations.append(
                rule["recommendation"]
            )

    if score < 0:
        score = 0

    if score >= 80:
        risk_level = "LOW"

    elif score >= 60:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    return {

        "risk_score": score,

        "risk_level": risk_level,

        "issues_found": issues,

        "recommendations": recommendations
    }