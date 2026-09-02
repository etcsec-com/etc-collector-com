package logger

import (
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// nouveauLoggerObserve rend un *Logger dont la sortie est capturable, sans
// toucher au logger global : les tests qui s'échangent un état global finissent
// par dépendre de leur ordre d'exécution.
func nouveauLoggerObserve() (*Logger, *observer.ObservedLogs) {
	noyau, logs := observer.New(zapcore.DebugLevel)
	zl := zap.New(noyau)
	return &Logger{SugaredLogger: zl.Sugar(), zap: zl}, logs
}

// TestMethodesStructurees verrouille le défaut trouvé le 2026-09-02 en rejouant
// les commandes de la documentation.
//
// Sans les méthodes de logger.go qui masquent celles du SugaredLogger embarqué,
// log.Warn("message", "clé", valeur) tombe sur zap.SugaredLogger.Warn, dont la
// signature est Warn(args ...any) : elle CONCATÈNE. La clé et la valeur se
// collaient au message, sans séparateur — et rien ne cassait, donc rien ne le
// signalait. Ce test échoue si ces méthodes disparaissent.
func TestMethodesStructurees(t *testing.T) {
	cas := []struct {
		nom     string
		appel   func(*Logger)
		niveau  zapcore.Level
		message string
	}{
		{"Debug", func(l *Logger) { l.Debug("msg debug", "clé", "valeur") }, zapcore.DebugLevel, "msg debug"},
		{"Info", func(l *Logger) { l.Info("msg info", "clé", "valeur") }, zapcore.InfoLevel, "msg info"},
		{"Warn", func(l *Logger) { l.Warn("msg warn", "clé", "valeur") }, zapcore.WarnLevel, "msg warn"},
		{"Error", func(l *Logger) { l.Error("msg error", "clé", "valeur") }, zapcore.ErrorLevel, "msg error"},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			lg, logs := nouveauLoggerObserve()
			c.appel(lg)

			entrees := logs.All()
			if len(entrees) != 1 {
				t.Fatalf("attendu 1 entrée, obtenu %d", len(entrees))
			}
			e := entrees[0]

			// Le message doit rester le message SEUL. S'il a absorbé la clé,
			// c'est la méthode concaténante de zap qui a été appelée.
			if e.Message != c.message {
				t.Errorf("message concaténé : %q (attendu %q) — la méthode structurée ne masque plus celle du SugaredLogger", e.Message, c.message)
			}
			if strings.Contains(e.Message, "clé") || strings.Contains(e.Message, "valeur") {
				t.Errorf("la paire clé/valeur s'est retrouvée DANS le message : %q", e.Message)
			}
			// Et elle doit être un champ structuré, pas du texte.
			champs := e.ContextMap()
			if v, ok := champs["clé"]; !ok || v != "valeur" {
				t.Errorf("paire clé/valeur absente des champs structurés : %v", champs)
			}
			if e.Level != c.niveau {
				t.Errorf("niveau %v, attendu %v", e.Level, c.niveau)
			}
		})
	}
}

// TestMethodeStructureeCasReel rejoue la ligne exacte qui a révélé le défaut :
// le warning émis par toute commande lancée sans config.yaml lisible.
func TestMethodeStructureeCasReel(t *testing.T) {
	lg, logs := nouveauLoggerObserve()
	err := errors.New("error reading config: open /etc/etc-collector/config.yaml: permission denied")

	lg.Warn("Failed to load config file, using defaults", "error", err)

	e := logs.All()[0]
	if e.Message != "Failed to load config file, using defaults" {
		t.Fatalf("message altéré : %q", e.Message)
	}
	// La sortie observée avant correction était :
	//   "Failed to load config file, using defaultserrorerror reading config: …"
	if strings.Contains(e.Message, "errorerror") {
		t.Fatalf("le défaut d'origine est revenu : %q", e.Message)
	}
	if got := e.ContextMap()["error"]; got != err.Error() {
		t.Errorf("l'erreur n'est pas un champ structuré : %v", e.ContextMap())
	}
}

// TestMessageSeulInchange : un appel à un seul argument doit traverser ces
// méthodes sans rien changer. 26 sites d'appel sont dans ce cas.
func TestMessageSeulInchange(t *testing.T) {
	lg, logs := nouveauLoggerObserve()
	lg.Info("message sans champ")

	e := logs.All()[0]
	if e.Message != "message sans champ" {
		t.Errorf("message altéré : %q", e.Message)
	}
	if len(e.ContextMap()) != 0 {
		t.Errorf("champs inattendus : %v", e.ContextMap())
	}
}
