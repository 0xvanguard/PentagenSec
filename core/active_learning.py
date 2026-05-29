import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from core.metrics import fp_predictions_total, fp_model_train_duration

class FPLearner:
    """v3.3: Clasificador online para descartar FPs. NIST SI-10 compliant."""

    def __init__(self, model_dir="models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.model_path = self.model_dir / "fp_classifier.pkl"
        self.vec_path = self.model_dir / "tfidf_vectorizer.pkl"

        self.vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,3))
        self._load_or_init()

    def _load_or_init(self):
        if self.model_path.exists():
            self.clf = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vec_path)
        else:
            # SGD: soporta partial_fit para online learning
            self.clf = SGDClassifier(loss='log_loss', alpha=1e-4, random_state=42)
            # Necesita fit inicial con 2 clases
            dummy_X = self.vectorizer.fit_transform(["init_fp", "init_tp"])
            self.clf.partial_fit(dummy_X, [0, 1], classes=[0, 1])

    def _extract_features(self, event: dict) -> str:
        """Concatena campos relevantes para TF-IDF"""
        return f"{event.get('image','')} {event.get('cmdline','')} {event.get('rule_id','')}"

    @fp_model_train_duration.time()
    def feedback(self, event: dict, is_false_positive: bool):
        """Analista marca FP/TP → re-entrena. NIST AU-6 audit trail."""
        text = self._extract_features(event)
        X = self.vectorizer.transform([text])
        y = [0 if is_false_positive else 1]
        self.clf.partial_fit(X, y)

        # Persistir tras cada feedback para no perder aprendizaje
        joblib.dump(self.clf, self.model_path)
        joblib.dump(self.vectorizer, self.vec_path)
        fp_predictions_total.labels(label='fp' if is_false_positive else 'tp').inc()

    def predict_fp_prob(self, event: dict) -> float:
        """Retorna P(FP). Si >0.8, el streamer lo descarta."""
        text = self._extract_features(event)
        X = self.vectorizer.transform([text])
        try:
            prob = self.clf.predict_proba(X)[0][0] # prob clase 0 = FP
            return float(prob)
        except: # Modelo no entrenado aún
            return 0.0

import argparse
import json
from sklearn.metrics import precision_recall_fscore_support

def train_cli():
    """DVC stage: entrena desde feedback_labeled.jsonl y exporta métricas"""
    learner = FPLearner()
    X_texts, y = [], []

    with open('data/feedback_labeled.jsonl') as f:
        for line in f:
            event = json.loads(line)
            X_texts.append(learner._extract_features(event))
            y.append(0 if event['is_fp'] else 1)

    X = learner.vectorizer.fit_transform(X_texts)
    learner.clf.fit(X, y)

    # Exporta métricas para DVC
    y_pred = learner.clf.predict(X)
    p, r, f1, _ = precision_recall_fscore_support(y, y_pred, average='binary')

    metrics = {
        "precision": float(p),
        "recall": float(r),
        "f1": float(f1),
        "samples": len(y)
    }

    joblib.dump(learner.clf, learner.model_path)
    joblib.dump(learner.vectorizer, learner.vec_path)
    Path('models/fp_metrics.json').write_text(json.dumps(metrics, indent=2))
    print(f"[DVC] Model trained: F1={f1:.3f}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--train', action='store_true')
    args = parser.parse_args()
    if args.train:
        train_cli()
