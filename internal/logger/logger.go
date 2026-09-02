// Package logger provides structured logging using zap
package logger

import (
	"fmt"
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Log file hardening — A_004 K7(c)+(d).
//
// (c) The log was created 0644, i.e. readable by every local account on a customer
// domain controller. It carries no passwords, but it does carry AD bind DNs, service
// account names and the signed update URL (?sig=…) — enough to be worth protecting on
// a host we do not own.
//
// (d) It never rotated. An append-only log on a DC is a disk-exhaustion incident
// waiting to happen on a machine we don't own; bounding it also caps GET_LOGS, whose
// readLastNLines does an unconditional os.ReadFile of the whole file.
const (
	logFileMode   os.FileMode = 0600
	logMaxSizeMB              = 20 // rotate past this size
	logMaxBackups             = 5  // keep at most 5 rotated files
	logMaxAgeDays             = 30 // …and drop anything older than 30 days
)

// newLogFileWriter returns a size-bounded, owner-only writer for filePath.
//
// The explicit create-and-chmod before handing the path to lumberjack is load-bearing
// twice over:
//   - lumberjack is lazy (it opens nothing until the first Write), so without this the
//     "log file is not writable → fall back to stderr" contract of NewWithFileFallback
//     would silently stop working;
//   - lumberjack copies the CURRENT file's mode onto every file it rotates into
//     (lumberjack.go openNew: `mode = info.Mode()`), so an existing 0644 log from an
//     older install would propagate 0644 forever. Tightening it first makes every
//     rotated file 0600 too.
func newLogFileWriter(filePath string) (io.Writer, error) {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFileMode)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", filePath, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close log file %s: %w", filePath, err)
	}
	// Covers the file that already existed at 0644 — os.OpenFile's mode applies only
	// to files it creates.
	if err := os.Chmod(filePath, logFileMode); err != nil {
		return nil, fmt.Errorf("tighten permissions on log file %s: %w", filePath, err)
	}

	return &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    logMaxSizeMB,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAgeDays,
		Compress:   true,
	}, nil
}

// Logger wraps zap.SugaredLogger for convenience
type Logger struct {
	*zap.SugaredLogger
	zap         *zap.Logger
	LogFilePath string // Path to log file (empty if no file logging)
}

// New creates a new logger instance
func New(level, format string) (*Logger, error) {
	// Parse level
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	// Configure encoder
	var encoderConfig zapcore.EncoderConfig
	var encoder zapcore.Encoder

	if format == "json" {
		encoderConfig = zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "timestamp"
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Create core
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		zapLevel,
	)

	// Create logger
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		SugaredLogger: zapLogger.Sugar(),
		zap:           zapLogger,
	}, nil
}

// NewWithFile creates a logger that writes to both stdout and a file.
// Console output uses the specified format, file output always uses JSON.
func NewWithFile(level, format, filePath string) (*Logger, error) {
	// Parse level
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	// Console encoder (same as New)
	var encoderConfig zapcore.EncoderConfig
	var consoleEncoder zapcore.Encoder

	if format == "json" {
		encoderConfig = zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "timestamp"
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		consoleEncoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
		consoleEncoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Owner-only, size-bounded log file (A_004 K7(c)+(d))
	file, err := newLogFileWriter(filePath)
	if err != nil {
		return nil, err
	}

	// File encoder: always JSON for structured log reading
	fileEncoderConfig := zap.NewProductionEncoderConfig()
	fileEncoderConfig.TimeKey = "timestamp"
	fileEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	fileEncoder := zapcore.NewJSONEncoder(fileEncoderConfig)

	// Tee core: stdout + file
	stdoutCore := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapLevel)
	fileCore := zapcore.NewCore(fileEncoder, zapcore.AddSync(file), zapLevel)
	core := zapcore.NewTee(stdoutCore, fileCore)

	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		SugaredLogger: zapLogger.Sugar(),
		zap:           zapLogger,
		LogFilePath:   filePath,
	}, nil
}

// NewWithStderr creates a logger that writes to both stdout and stderr.
// Console output uses the specified format, stderr always uses JSON.
// Used as fallback when file logging is unavailable.
func NewWithStderr(level, format string) (*Logger, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	// Console encoder for stdout
	var consoleEncoder zapcore.Encoder
	if format == "json" {
		ec := zap.NewProductionEncoderConfig()
		ec.TimeKey = "timestamp"
		ec.EncodeTime = zapcore.ISO8601TimeEncoder
		consoleEncoder = zapcore.NewJSONEncoder(ec)
	} else {
		ec := zap.NewDevelopmentEncoderConfig()
		ec.EncodeLevel = zapcore.CapitalColorLevelEncoder
		ec.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
		consoleEncoder = zapcore.NewConsoleEncoder(ec)
	}

	// JSON encoder for stderr
	stderrConfig := zap.NewProductionEncoderConfig()
	stderrConfig.TimeKey = "timestamp"
	stderrConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	stderrEncoder := zapcore.NewJSONEncoder(stderrConfig)

	stdoutCore := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapLevel)
	stderrCore := zapcore.NewCore(stderrEncoder, zapcore.AddSync(os.Stderr), zapLevel)
	core := zapcore.NewTee(stdoutCore, stderrCore)

	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		SugaredLogger: zapLogger.Sugar(),
		zap:           zapLogger,
	}, nil
}

// NewWithFileFallback creates a logger that writes to stdout + file.
// If file creation fails, it falls back to stdout + stderr.
// Returns the logger, the actual log file path used (empty if fallback), and any error.
func NewWithFileFallback(level, format, filePath string) (*Logger, string, error) {
	l, err := NewWithFile(level, format, filePath)
	if err == nil {
		return l, filePath, nil
	}

	// File logging failed — notify via stderr and fall back
	fmt.Fprintf(os.Stderr, "WARNING: Cannot create log file %s: %v. Falling back to stderr.\n", filePath, err)

	l, err2 := NewWithStderr(level, format)
	if err2 != nil {
		// Last resort: stdout only
		l, _ = New(level, format)
		return l, "", fmt.Errorf("file logging failed (%v), stderr fallback also failed (%v), using stdout only", err, err2)
	}
	return l, "", fmt.Errorf("file logging failed: %w, using stderr fallback", err)
}

// NewNop creates a no-op logger for testing
func NewNop() *Logger {
	return &Logger{
		SugaredLogger: zap.NewNop().Sugar(),
		zap:           zap.NewNop(),
	}
}

// Zap returns the underlying zap.Logger
func (l *Logger) Zap() *zap.Logger {
	return l.zap
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.zap.Sync()
}

// With creates a child logger with additional fields
func (l *Logger) With(args ...interface{}) *Logger {
	return &Logger{
		SugaredLogger: l.SugaredLogger.With(args...),
		zap:           l.zap,
	}
}

// Named creates a named child logger
func (l *Logger) Named(name string) *Logger {
	return &Logger{
		SugaredLogger: l.SugaredLogger.Named(name),
		zap:           l.zap.Named(name),
	}
}

// Global logger instance
var globalLogger *Logger

// SetGlobal sets the global logger
func SetGlobal(l *Logger) {
	globalLogger = l
}

// Global returns the global logger
func Global() *Logger {
	if globalLogger == nil {
		globalLogger, _ = New("info", "console")
	}
	return globalLogger
}

// Package-level convenience functions

// Debug logs a debug message
func Debug(msg string, args ...interface{}) {
	Global().Debugw(msg, args...)
}

// Info logs an info message
func Info(msg string, args ...interface{}) {
	Global().Infow(msg, args...)
}

// Warn logs a warning message
func Warn(msg string, args ...interface{}) {
	Global().Warnw(msg, args...)
}

// Error logs an error message
func Error(msg string, args ...interface{}) {
	Global().Errorw(msg, args...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, args ...interface{}) {
	Global().Fatalw(msg, args...)
}

// ─── Méthodes structurées sur *Logger ────────────────────────────────────────
//
// Elles MASQUENT délibérément Debug/Info/Warn/Error du *zap.SugaredLogger
// embarqué, et c'est tout leur intérêt.
//
// Le piège, trouvé le 2026-09-02 en rejouant les commandes de la documentation :
// les fonctions de paquet ci-dessus (logger.Warn) appellent bien Warnw, la forme
// structurée. Mais un appel de MÉTHODE — log.Warn("message", "clé", valeur) —
// tombait sur zap.SugaredLogger.Warn, dont la signature est Warn(args ...any) :
// elle CONCATÈNE ses arguments à la façon de fmt.Sprint. La clé et la valeur
// étaient donc collées au message, sans séparateur ni guillemets. Sortie réelle
// de `etc-collector status`, au niveau de l'octet :
//
//     Failed to load config file, using defaultserrorerror reading config: open …
//
// La même ligne, une fois passée par Warnw :
//
//     Failed to load config file, using defaults  {"error": "error reading config: open …"}
//
// Deux choses rendaient ce défaut difficile à voir. D'abord il ne casse rien :
// pas d'erreur, pas de test rouge, seulement une ligne illisible. Ensuite le
// paquet contenait déjà la bonne version — un test écrit avec logger.Warn passe,
// alors que le produit, lui, appelle log.Warn. C'est le premier message que voit
// quiconque lance le binaire sans config.yaml lisible.
//
// 37 sites d'appel étaient concernés (mesuré). Corriger ici les couvre tous sans
// toucher un seul d'entre eux ; aucun n'attendait une concaténation : tous les
// appels à plusieurs arguments passent des paires clé/valeur. Un appel à un seul
// argument traverse ces méthodes sans changer de comportement.
//
// Pour la forme printf, Debugf/Infof/Warnf/Errorf restent disponibles : elles ne
// sont pas masquées.

// Debug logs a debug message with structured key/value pairs.
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.SugaredLogger.Debugw(msg, args...)
}

// Info logs an info message with structured key/value pairs.
func (l *Logger) Info(msg string, args ...interface{}) {
	l.SugaredLogger.Infow(msg, args...)
}

// Warn logs a warning message with structured key/value pairs.
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.SugaredLogger.Warnw(msg, args...)
}

// Error logs an error message with structured key/value pairs.
func (l *Logger) Error(msg string, args ...interface{}) {
	l.SugaredLogger.Errorw(msg, args...)
}

// Fatal logs a fatal message with structured key/value pairs, then exits.
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.SugaredLogger.Fatalw(msg, args...)
}
