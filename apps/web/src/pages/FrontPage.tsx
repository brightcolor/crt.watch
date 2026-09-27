import { ArrowRight, Bell, Radar, Server, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { BrandMark } from "../components/BrandMark";

/* The public page speaks German and addresses the reader directly; the
   application behind the sign-in stays English. The subtree carries lang="de"
   so screen readers switch for it without changing the document language. */

export function FrontPage({ setupRequired, registrationEnabled, onAuth, onRegister }: {
  setupRequired: boolean;
  registrationEnabled: boolean;
  onAuth: () => void;
  onRegister: () => void;
}) {
  const primaryAction = setupRequired ? onAuth : registrationEnabled ? onRegister : onAuth;
  const primaryLabel = setupRequired
    ? "Ersten Zugang anlegen"
    : registrationEnabled ? "Konto anlegen" : "Zur Übersicht";
  return (
    <main className="frontpage" lang="de">
      <header className="frontpage-nav">
        <a className="frontpage-brand" href="#top" aria-label="crt.watch Startseite">
          <span><BrandMark size={19} /></span>
          <strong>crt.watch</strong>
        </a>
        <nav aria-label="Seitennavigation">
          <a href="#features">Was geprüft wird</a>
          {!setupRequired && registrationEnabled && <button className="btn btn-outline-secondary" type="button" onClick={onRegister}>Konto anlegen</button>}
          <button className="btn btn-primary" type="button" onClick={onAuth}>{setupRequired ? "Einrichten" : "Anmelden"}</button>
        </nav>
      </header>

      <section className="frontpage-hero" id="top">
        <div className="frontpage-copy">
          <span className="eyebrow">Zertifikate und Dienste im Blick</span>
          <h1>Du weißt vom Zertifikat, bevor der Kunde anruft.</h1>
          <p>
            crt.watch prüft Ablaufdatum, Kette, Namen und TLS-Einstellungen deiner Zertifikate —
            und gleich die Dienste dahinter: HTTPS, Mailserver mit STARTTLS, SSH, DNS und Anmeldungen.
            Die Meldung kommt per Mail, Chat oder Webhook, solange noch Zeit zum Handeln ist.
          </p>
          <div className="frontpage-actions">
            <button className="btn btn-primary btn-lg" type="button" onClick={primaryAction}>{primaryLabel} <ArrowRight size={16} /></button>
            <a className="btn btn-outline-secondary" href="#features">Was geprüft wird</a>
          </div>
        </div>
        <div className="frontpage-visual" aria-label="Übersicht in crt.watch">
          <div className="visual-header"><span></span><span></span><span></span></div>
          <div className="visual-score">
            <strong>Alle wichtigen Zertifikate erfasst</strong>
            <small>Laufende Prüfungen, Restlaufzeit, TLS-Note, DNS-Vergleich</small>
          </div>
          {[
            ["mail.example.net", "OK", "TLS A, 62 Tage übrig"],
            ["api.example.com", "Warnung", "Zertifikat hat gewechselt"],
            ["imap.example.org", "OK", "STARTTLS-Anmeldung erfolgreich"]
          ].map(([host, status, detail]) => (
            <div className={`visual-row visual-${status === "OK" ? "ok" : "warning"}`} key={host}>
              <span>{status}</span>
              <strong>{host}</strong>
              <small>{detail}</small>
            </div>
          ))}
        </div>
      </section>

      <section className="frontpage-strip" aria-label="Kennzahlen">
        <div><strong>30 / 14 / 7</strong><span>Tage Vorwarnung, einstellbar</span></div>
        <div><strong>SMTP, IMAP, POP3</strong><span>STARTTLS und direktes TLS</span></div>
        <div><strong>Statusseiten</strong><span>für Kunden sichtbar</span></div>
        <div><strong>Prometheus</strong><span>Kennzahlen für Grafana</span></div>
      </section>

      <section className="frontpage-section" id="features">
        <div>
          <span className="eyebrow">Für Betreiber gebaut</span>
          <h2>Zertifikate überwachen und die Dienste gleich mit.</h2>
          <p className="muted">Ein ruhiger Leitstand für den Zertifikatsbetrieb: so viele Meldungen wie nötig, so wenige wie möglich.</p>
        </div>
        <div className="frontpage-grid">
          <Feature icon={<ShieldCheck />} title="Zertifikate" text="Restlaufzeit, Namen und SANs, Aussteller und Fingerabdruck, die ganze Kette bis zur Wurzel und eine Note für die TLS-Einstellung." />
          <Feature icon={<Server />} title="Dienste" text="HTTPS, TCP mit TLS, SMTP, IMAP, POP3, FTP, SSH und DNS, dazu Anmeldungen und beide Wege für Mail: STARTTLS und direktes TLS." />
          <Feature icon={<Bell />} title="Meldungen mit Ruhe" text="Empfänger je Kennzeichnung, keine Wiederholung derselben Sache, Entwarnung nach der Behebung, Eskalation nach Zeit, Ruhezeiten und Wartungsfenster." />
          <Feature icon={<Radar />} title="Veränderungen" text="Certificate Transparency im Blick, Vergleich mehrerer DNS-Auflöser, SSL-Labs-Bewertung und eine Nachricht, sobald sich etwas ändert." />
        </div>
      </section>

      <section className="frontpage-close">
        <div>
          <span className="eyebrow">Anfangen</span>
          <h2>Ein Zertifikat eintragen reicht für den Anfang.</h2>
          <p>Trag deine erste Adresse ein, und du siehst innerhalb einer Minute, wie es um sie steht.</p>
        </div>
        <button className="btn btn-primary btn-lg" type="button" onClick={primaryAction}>{primaryLabel} <ArrowRight size={16} /></button>
      </section>
    </main>
  );
}

function Feature({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return (
    <article className="frontpage-card">
      <span>{icon}</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </article>
  );
}
