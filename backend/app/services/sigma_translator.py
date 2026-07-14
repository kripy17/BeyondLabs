from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import LuceneBackend, EqlBackend, ESQLBackend
from sigma.backends.loki import LogQLBackend
from sigma.backends.netwitness import NetWitnessBackend

BACKENDS = {
    "splunk": SplunkBackend,
    "elasticsearch_lucene": LuceneBackend,
    "elastic_eql": EqlBackend,
    "elastic_esql": ESQLBackend,
    "loki": LogQLBackend,
    "netwitness": NetWitnessBackend,
}

BACKEND_LABELS = {
    "splunk": "Splunk SPL",
    "elasticsearch_lucene": "Elasticsearch Lucene",
    "elastic_eql": "Elastic EQL",
    "elastic_esql": "Elastic ES|QL",
    "loki": "Loki LogQL",
    "netwitness": "NetWitness",
}


def translate_sigma(sigma_yaml: str, target: str) -> dict:
    errors = []
    queries = []

    if target not in BACKENDS:
        return {"target": target, "queries": [], "errors": [f"Unsupported backend: {target}"]}

    try:
        sigma_collection = SigmaCollection.from_yaml(sigma_yaml)
    except Exception as e:
        return {"target": target, "queries": [], "errors": [f"Invalid Sigma YAML: {e}"]}

    try:
        backend_cls = BACKENDS[target]
        backend = backend_cls()
        result = backend.convert(sigma_collection)
        if isinstance(result, list):
            queries = result
        elif isinstance(result, str):
            queries = [result]
    except Exception as e:
        errors.append(f"Translation error: {e}")

    return {
        "target": target,
        "target_label": BACKEND_LABELS.get(target, target),
        "queries": queries,
        "errors": errors,
    }


def list_backends() -> list[dict]:
    return [{"id": k, "label": v} for k, v in BACKEND_LABELS.items()]
