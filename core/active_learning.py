import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from prometheus_client import Counter, Histogram
import numpy as np

fp_predictions = Counter('antigravity_fp_predictions_total', 'FP predictions', ['label'])
fp_train_time = Histogram('antigravity_fp_train_duration_seconds', 'FP model training time')

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

    @fp_train_time.time()
    def feedback(self, event: dict, is_false_positive: bool):
        """Analista marca FP/TP → re-entrena. NIST AU-6 audit trail."""
        text = self._extract_features(event)
        X = self.vectorizer.transform([text])
        y = [0 if is_false_positive else 1]
        self.clf.partial_fit(X, y)

        # Persistir tras cada feedback para no perder aprendizaje
        joblib.dump(self.clf, self.model_path)
        joblib.dump(self.vectorizer, self.vec_path)
        fp_predictions.labels(label='fp' if is_false_positive else 'tp').inc()

    def predict_fp_prob(self, event: dict) -> float:
        """Retorna P(FP). Si >0.8, el streamer lo descarta."""
        text = self._extract_features(event)
        X = self.vectorizer.transform([text])
        try:
            prob = self.clf.predict_proba(X)[0][0] # prob clase 0 = FP
            return float(prob)
        except: # Modelo no entrenado aún
            return 0.0
