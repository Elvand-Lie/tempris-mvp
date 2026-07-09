import { useEffect, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  Award,
  CheckCircle2,
  ClipboardCheck,
  Clock,
  FileText,
  Server,
  Shield,
  ShieldAlert,
  Target,
  XCircle,
} from 'lucide-react';
import heroArt from '../assets/hero.png';

const contactEmail = 'lohsherie@yahoo.com.sg';

const navLinks = [
  ['safe-harbor', 'Safe Harbor'],
  ['scope', 'Scope'],
  ['rules', 'Rules'],
  ['submit', 'Submit'],
  ['rewards', 'Rewards'],
  ['disclosure', 'Disclosure'],
  ['hof', 'Hall of Fame'],
];

const metaItems = [
  ['Organisation', 'Tempris Technology Pte. Ltd.'],
  ['UEN', '202613990D'],
  ['Programme Type', 'VDP + invited testing'],
  ['Policy Version', 'v1.0 - June 2026'],
  ['Safe Harbor', 'Full - disclose.io aligned'],
];

const scopeAssets = [
  ['sandbox.tempris.tech', 'Web Application', 'Tier 2', 'Primary testing target for invited researchers. All sandbox features are in scope.'],
  ['tempris.tech', 'Public Web', 'Tier 1', 'Report only. Do not perform active testing without invitation.'],
  ['api.tempris.tech', 'REST API', 'Tier 2', 'Authentication, authorisation, injection, and business logic testing.'],
  ['Tempris Mobile Apps', 'iOS / Android', 'Tier 1', 'If published, report findings through the official contact channel.'],
  ['Tempris Open Source Code', 'Source Code', 'Tier 1', 'Any publicly available Tempris repositories.'],
];

const outOfScope = [
  'Production client environments and any system not operated by Tempris',
  'Third-party services and infrastructure, including cloud providers, payment processors, and DNS registrars',
  'Social engineering attacks against Tempris employees, contractors, or clients',
  'Physical security testing of offices, data centres, or hardware',
  'Denial of Service or Distributed Denial of Service testing against any Tempris system',
  'Automated scanning that generates excessive traffic volumes',
  'Accessing, exfiltrating, or retaining real user data beyond what is necessary to demonstrate the vulnerability',
  'Testing against systems of clients or partners without their explicit written permission',
  'Email phishing, vishing, or smishing directed at Tempris personnel',
];

const mustDo = [
  'Report the vulnerability to Tempris before disclosing it to anyone else',
  'Provide enough detail for reproduction, including steps, payloads, screenshots, or recordings where applicable',
  'Stop testing immediately if you encounter real production data or client data',
  'Keep vulnerability details confidential until a fix is confirmed or the coordinated disclosure period expires',
  'Use test accounts and test data you created yourself wherever possible',
  'Act in good faith with the goal of improving security and avoiding harm',
];

const mustNotDo = [
  'Exploit a vulnerability beyond the minimum necessary to demonstrate its existence',
  'Access, copy, modify, delete, or retain data beyond what is needed to prove the issue',
  'Disrupt or degrade the availability of any Tempris system or service',
  'Perform Denial of Service testing of any kind',
  'Use automated scanners without prior written approval from Tempris',
  'Target, involve, or harm third parties',
  'Share details of a finding before coordinated disclosure is agreed',
  'Use access gained through research for any purpose other than reporting to Tempris',
  'Conduct physical testing, social engineering, or credential harvesting through non-technical means',
];

const reportItems = [
  'Vulnerability type, such as SQLi, XSS, IDOR, SSRF, auth bypass, or logic flaw',
  'Affected asset, URL, endpoint, API route, or component',
  'Numbered steps to reproduce with enough detail for independent validation',
  'Proof of concept, including screenshots, screen recording, or a code snippet where useful',
  'Impact assessment explaining what an attacker could do and what data or systems are at risk',
  'Suggested remediation if you have one, especially for complex findings',
  'Your contact details and preferred name or handle for recognition',
];

const rewardTiers = [
  ['Critical', 'Hall of Fame + Letter of Recommendation', 'Named public listing plus a formal signed recommendation letter on Tempris letterhead.', 'danger'],
  ['High', 'Hall of Fame + Certificate', 'Named public listing plus a Certificate of Responsible Disclosure.', 'warning'],
  ['Medium', 'Hall of Fame Listing', 'Named public listing on this page and written acknowledgement from Tempris.', 'primary'],
  ['Low / Info', 'Written Acknowledgement', 'Personal acknowledgement from the Tempris security team.', 'muted'],
];

const severityRows = [
  ['Critical', '9.0 - 10.0', 'RCE, authentication bypass granting admin access, mass data exfiltration, account takeover at scale'],
  ['High', '7.0 - 8.9', 'SQLi, stored XSS, SSRF with internal access, IDOR to sensitive data, privilege escalation'],
  ['Medium', '4.0 - 6.9', 'Reflected XSS, CSRF on sensitive actions, limited-impact IDOR, information disclosure'],
  ['Low', '0.1 - 3.9', 'Missing security headers, verbose error messages, low-risk misconfiguration, best-practice deviations'],
];

const outOfRecognition = [
  'Missing rate limiting without demonstrated account enumeration or brute-force feasibility',
  'Self-XSS that requires a victim to execute code in their own browser',
  'Clickjacking without a demonstrated sensitive action',
  'Password or account policy observations without demonstrated exploitability',
  'Unconfirmed automated scanner output without manual validation',
  'Theoretical vulnerabilities without evidence of exploitability',
  'Library or framework version disclosure without a demonstrated vulnerability',
  'SPF, DMARC, or DKIM issues without demonstrated email spoofing impact',
];

const disclosureTimeline = [
  ['Day 0', 'Submission received', 'Automated acknowledgement is sent immediately. Human acknowledgement follows within 5 business days.'],
  ['Day 1-10', 'Triage', 'Tempris confirms reproducibility, assigns internal severity, and asks for additional information if needed.'],
  ['Day 10-30', 'Remediation', 'Critical and High findings are prioritised for immediate patching. Status updates are provided at least every 14 days during active remediation.'],
  ['Day 30-90', 'Complex findings', 'For issues requiring architectural changes, Tempris agrees a remediation timeline with the researcher.'],
  ['Day 90', 'Disclosure deadline', 'If a fix has not been applied within 90 days, the researcher may disclose the finding publicly regardless of fix status.'],
  ['Post-fix', 'Coordinated public disclosure', 'After a fix is deployed, Tempris coordinates timing, credit language, and Hall of Fame listing. Default notice period is 7 days.'],
];

const governance = [
  'This policy is reviewed at least annually, or after a material change to product, infrastructure, or regulatory environment.',
  'Changes to scope, safe harbor terms, or reward tiers will be announced with at least 14 days notice before taking effect.',
  'Open submissions are governed by the terms in effect at the time of submission.',
  `Policy disputes should be directed to ${contactEmail} with the subject line "Policy Dispute".`,
  'Tempris will never retroactively apply more restrictive terms to a finding already in triage.',
];

const securityTxt = `# Tempris Technology Pte. Ltd. - security.txt
# RFC 9116 compliant | VDP + coordinated disclosure
# Generated: June 2026 | Review annually

Contact: mailto:${contactEmail}
Contact: https://tempris.tech/security
Acknowledgments: https://tempris.tech/security#hof
Policy: https://tempris.tech/security
Canonical: https://tempris.tech/.well-known/security.txt
Expires: 2027-06-30T00:00:00Z
Preferred-Languages: en`;

function Section({
  id,
  eyebrow,
  title,
  children,
}: {
  id: string;
  eyebrow: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-24 border-t border-border py-12 md:py-14">
      <div className="mb-5">
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-primary-400">{eyebrow}</div>
        <h2 className="max-w-3xl text-2xl font-bold tracking-tight text-text-main md:text-3xl">{title}</h2>
      </div>
      <div className="space-y-5 text-sm leading-7 text-text-muted md:text-[15px]">{children}</div>
    </section>
  );
}

function TonePill({ tone, children }: { tone: string; children: ReactNode }) {
  const tones: Record<string, string> = {
    primary: 'border-primary-500/25 bg-primary-500/10 text-primary-400',
    danger: 'border-danger/25 bg-danger/10 text-danger',
    warning: 'border-warning/25 bg-warning/10 text-warning',
    muted: 'border-border bg-surfaceHover text-text-muted',
  };

  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${tones[tone] || tones.muted}`}>
      {children}
    </span>
  );
}

function Note({ tone = 'primary', children }: { tone?: 'primary' | 'warning' | 'danger' | 'muted'; children: ReactNode }) {
  const tones = {
    primary: 'border-primary-500/25 bg-primary-500/5 text-text-main',
    warning: 'border-warning/30 bg-warning/5 text-text-main',
    danger: 'border-danger/30 bg-danger/5 text-text-main',
    muted: 'border-border bg-surface text-text-main',
  };

  return <div className={`rounded-lg border p-5 text-sm leading-7 ${tones[tone]}`}>{children}</div>;
}

function PolicyList({ items, mode = 'neutral' }: { items: string[]; mode?: 'neutral' | 'ok' | 'no' }) {
  const Icon = mode === 'ok' ? CheckCircle2 : mode === 'no' ? XCircle : Target;
  const color = mode === 'ok' ? 'text-success' : mode === 'no' ? 'text-danger' : 'text-primary-400';

  return (
    <ul className="divide-y divide-border rounded-lg border border-border bg-surface">
      {items.map((item) => (
        <li key={item} className="flex gap-3 px-4 py-3">
          <Icon className={`mt-1 h-4 w-4 shrink-0 ${color}`} />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

function PublicHeader() {
  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/95 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center gap-5 px-4 py-3 md:px-8">
        <a href="#top" className="flex shrink-0 items-center gap-3 text-text-main">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary-500/25 bg-primary-500/10 text-primary-400">
            <ShieldAlert size={19} />
          </span>
          <span className="text-sm font-bold tracking-[0.2em]">TEMPRIS</span>
        </a>

        <nav className="hidden min-w-0 flex-1 items-center gap-1 overflow-x-auto lg:flex">
          {navLinks.map(([id, label]) => (
            <a
              key={id}
              href={`#${id}`}
              className="rounded px-3 py-2 text-xs font-semibold uppercase tracking-wide text-text-muted transition-colors hover:bg-surfaceHover hover:text-text-main"
            >
              {label}
            </a>
          ))}
        </nav>

        <a
          href={`mailto:${contactEmail}?subject=Tempris%20Security%20Report`}
          className="ml-auto inline-flex items-center gap-2 rounded-lg border border-primary-500/25 bg-primary-500/10 px-3 py-2 text-xs font-semibold text-primary-400 transition-colors hover:bg-primary-500/20"
        >
          <FileText size={15} />
          Report Finding
        </a>
      </div>
    </header>
  );
}

export default function SecurityPolicy() {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = 'Vulnerability Disclosure Policy - Tempris Technology';
    return () => {
      document.title = previousTitle;
    };
  }, []);

  return (
    <div className="min-h-screen bg-background text-text-main">
      <PublicHeader />

      <main id="top">
        <section className="border-b border-border bg-background">
          <div className="mx-auto grid max-w-7xl gap-10 px-4 py-14 md:px-8 md:py-20 lg:grid-cols-[1fr_360px]">
            <div className="max-w-4xl">
              <div className="mb-4 inline-flex items-center gap-2 rounded border border-primary-500/25 bg-primary-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-primary-400">
                <span className="h-1.5 w-1.5 rounded-full bg-primary-400" />
                Program Active
              </div>
              <h1 className="max-w-4xl text-4xl font-black tracking-tight text-text-main md:text-6xl">
                Vulnerability Disclosure Policy
              </h1>
              <p className="mt-5 max-w-2xl text-base leading-8 text-text-muted md:text-lg">
                Tempris Technology welcomes good-faith security research. This policy defines how to responsibly test our platform,
                how reports are handled, and what researchers receive in return.
              </p>

              <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                {metaItems.map(([label, value]) => (
                  <div key={label} className="rounded-lg border border-border bg-surface p-4">
                    <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">{label}</div>
                    <div className="text-sm font-semibold text-text-main">{value}</div>
                  </div>
                ))}
              </div>
            </div>

            <aside className="relative overflow-hidden rounded-lg border border-border bg-surface p-6">
              <img
                src={heroArt}
                alt=""
                aria-hidden="true"
                className="absolute right-4 top-4 h-28 w-auto opacity-30"
              />
              <div className="relative">
                <div className="mb-5 flex h-11 w-11 items-center justify-center rounded-lg border border-primary-500/25 bg-primary-500/10 text-primary-400">
                  <Shield size={22} />
                </div>
                <h2 className="text-lg font-bold">Researcher quick start</h2>
                <div className="mt-5 space-y-4 text-sm text-text-muted">
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">Primary contact</div>
                    <a className="mt-1 block font-mono text-primary-400" href={`mailto:${contactEmail}`}>
                      {contactEmail}
                    </a>
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">Initial response</div>
                    <div className="mt-1 font-semibold text-text-main">Within 5 business days</div>
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">Testing model</div>
                    <div className="mt-1 font-semibold text-text-main">Public VDP + invited sandbox testing</div>
                  </div>
                </div>
              </div>
            </aside>
          </div>
        </section>

        <div className="mx-auto max-w-5xl px-4 md:px-8">
          <Section id="intro" eyebrow="01 - Introduction" title="Our commitment to researchers">
            <p>
              Tempris Technology Pte. Ltd. builds a Continuous Threat Exposure Management platform for regulated financial institutions in Singapore.
              We hold ourselves to the same security standard we provide to clients.
            </p>
            <p>
              If you find a vulnerability in a Tempris-operated system, report it to us responsibly. If you follow this policy,
              Tempris will not pursue legal action, will acknowledge your work, and will work to fix valid findings.
            </p>
            <Note>
              This policy is published in the spirit of the disclose.io framework and is designed around Full Safe Harbor with Coordinated Disclosure.
            </Note>
          </Section>

          <Section id="safe-harbor" eyebrow="02 - Safe Harbor" title="Authorised good-faith research">
            <p>
              Safe Harbor terms apply to security research conducted under this policy. These terms are based on disclose.io core VDP principles
              and cover the four mandatory tenets below.
            </p>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-border bg-surface p-5">
                <Shield className="mb-4 h-5 w-5 text-primary-400" />
                <h3 className="font-semibold text-text-main">Anti-hacking authorisation</h3>
                <p className="mt-2 text-sm text-text-muted">
                  Tempris authorises good-faith testing within scope and will not initiate legal action under anti-hacking laws for compliant research.
                </p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <Activity className="mb-4 h-5 w-5 text-primary-400" />
                <h3 className="font-semibold text-text-main">Anti-circumvention exemption</h3>
                <p className="mt-2 text-sm text-text-muted">
                  Tempris will not pursue anti-circumvention claims for research conducted in good faith and in accordance with this policy.
                </p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <ClipboardCheck className="mb-4 h-5 w-5 text-primary-400" />
                <h3 className="font-semibold text-text-main">TOS and AUP exemption</h3>
                <p className="mt-2 text-sm text-text-muted">
                  Tempris exempts compliant researchers from restrictions in terms or acceptable-use policies that would otherwise prohibit security testing.
                </p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <Award className="mb-4 h-5 w-5 text-primary-400" />
                <h3 className="font-semibold text-text-main">Good-faith acknowledgement</h3>
                <p className="mt-2 text-sm text-text-muted">
                  Tempris treats valid reports fairly, acknowledges researchers promptly, and works collaboratively through remediation and disclosure.
                </p>
              </div>
            </div>

            <Note>
              <strong className="text-text-main">Formal statement.</strong> Tempris considers research conducted under this policy to be authorised activity and will not initiate or recommend legal action for activities that comply with these terms.
              If a third party initiates legal action connected to compliant research, Tempris will take steps to make it known that the activity was conducted under this policy.
            </Note>
            <Note tone="muted">
              <strong className="text-text-main">Singapore law context.</strong> This policy operates within Singapore law, including the Computer Misuse and Cybersecurity Act, the Personal Data Protection Act, and MAS Technology Risk Management Guidelines.
              It does not constitute legal advice.
            </Note>
          </Section>

          <Section id="structure" eyebrow="03 - Programme Structure" title="Two tiers, one policy">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-primary-500/25 bg-primary-500/5 p-5">
                <TonePill tone="primary">Tier 1</TonePill>
                <h3 className="mt-4 text-lg font-semibold text-text-main">Public VDP - always open</h3>
                <p className="mt-2">
                  Anyone may report a vulnerability at any time through <a className="text-primary-400 hover:underline" href={`mailto:${contactEmail}`}>{contactEmail}</a>. No invitation or screening is required.
                  Tier 1 exists so legitimate finders always have a channel.
                </p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <TonePill tone="muted">Tier 2</TonePill>
                <h3 className="mt-4 text-lg font-semibold text-text-main">Invited testing - sandbox.tempris.tech</h3>
                <p className="mt-2">
                  Invited researchers may conduct active hands-on testing against the sandbox environment and receive expanded scope,
                  direct communication, Hall of Fame eligibility, and recommendation letters for eligible findings.
                </p>
              </div>
            </div>
          </Section>

          <Section id="scope" eyebrow="04 - Scope" title="What researchers may test">
            <p>The following assets are explicitly in scope. The public VDP accepts reports across the Tempris attack surface, while active testing is restricted to approved targets.</p>

            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full min-w-[760px] border-collapse text-left text-sm">
                <thead className="bg-surface text-[11px] uppercase tracking-[0.14em] text-text-muted">
                  <tr>
                    <th className="border-b border-border px-4 py-3">Asset</th>
                    <th className="border-b border-border px-4 py-3">Type</th>
                    <th className="border-b border-border px-4 py-3">Tier</th>
                    <th className="border-b border-border px-4 py-3">Notes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border bg-surface/70">
                  {scopeAssets.map(([asset, type, tier, notes]) => (
                    <tr key={asset} className="align-top">
                      <td className="px-4 py-3 font-mono text-primary-400">{asset}</td>
                      <td className="px-4 py-3 text-text-main">{type}</td>
                      <td className="px-4 py-3"><TonePill tone={tier === 'Tier 2' ? 'muted' : 'primary'}>{tier}</TonePill></td>
                      <td className="px-4 py-3 text-text-muted">{notes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3 className="pt-4 text-lg font-semibold text-text-main">Out of scope</h3>
            <PolicyList items={outOfScope} mode="no" />

            <Note tone="warning">
              <strong className="text-text-main">Scope ambiguity.</strong> If you are unsure whether a system or action is within scope,
              ask first at <a className="text-primary-400 hover:underline" href={`mailto:${contactEmail}`}>{contactEmail}</a>.
            </Note>
          </Section>

          <Section id="rules" eyebrow="05 - Rules of Engagement" title="How to conduct good-faith research">
            <p>These rules protect researchers, Tempris clients, and Tempris systems while still allowing useful security findings to be reported.</p>
            <div className="grid gap-5 lg:grid-cols-2">
              <div>
                <h3 className="mb-3 text-lg font-semibold text-text-main">You must</h3>
                <PolicyList items={mustDo} mode="ok" />
              </div>
              <div>
                <h3 className="mb-3 text-lg font-semibold text-text-main">You must not</h3>
                <PolicyList items={mustNotDo} mode="no" />
              </div>
            </div>
          </Section>

          <Section id="submit" eyebrow="06 - Reporting" title="How to submit a finding">
            <p>All vulnerability reports should be sent through the official contact channel. Tempris triages every submission and responds within 5 business days.</p>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-lg border border-border bg-surface p-5">
                <FileText className="mb-4 h-5 w-5 text-primary-400" />
                <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">Primary channel</div>
                <a className="mt-2 block break-words font-mono text-sm text-primary-400" href={`mailto:${contactEmail}`}>{contactEmail}</a>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <Shield className="mb-4 h-5 w-5 text-primary-400" />
                <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">Sensitive findings</div>
                <div className="mt-2 text-sm font-semibold text-text-main">Request encrypted exchange</div>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <Clock className="mb-4 h-5 w-5 text-primary-400" />
                <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">Response SLA</div>
                <div className="mt-2 text-sm font-semibold text-text-main">5 business days</div>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <Server className="mb-4 h-5 w-5 text-primary-400" />
                <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">Language</div>
                <div className="mt-2 text-sm font-semibold text-text-main">English preferred</div>
              </div>
            </div>

            <h3 className="pt-4 text-lg font-semibold text-text-main">What to include</h3>
            <PolicyList items={reportItems} />
            <p>You do not need to calculate CVSS. Tempris scores findings internally and welcomes severity discussion if relevant context is missing.</p>
          </Section>

          <Section id="rewards" eyebrow="07 - Severity and Rewards" title="Recognition model">
            <p>
              Tempris does not currently offer cash rewards. Instead, the programme offers professional recognition that researchers can use as
              public evidence of responsible disclosure work.
            </p>

            <div className="grid gap-4 md:grid-cols-2">
              {rewardTiers.map(([severity, reward, description, tone]) => (
                <div key={severity} className="rounded-lg border border-border bg-surface p-5">
                  <TonePill tone={tone}>{severity}</TonePill>
                  <h3 className="mt-4 font-semibold text-text-main">{reward}</h3>
                  <p className="mt-2 text-sm text-text-muted">{description}</p>
                </div>
              ))}
            </div>

            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full min-w-[700px] border-collapse text-left text-sm">
                <thead className="bg-surface text-[11px] uppercase tracking-[0.14em] text-text-muted">
                  <tr>
                    <th className="border-b border-border px-4 py-3">Severity</th>
                    <th className="border-b border-border px-4 py-3">CVSS Range</th>
                    <th className="border-b border-border px-4 py-3">Example findings</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border bg-surface/70">
                  {severityRows.map(([severity, range, examples]) => (
                    <tr key={severity}>
                      <td className="px-4 py-3"><TonePill tone={severity === 'Critical' ? 'danger' : severity === 'High' ? 'warning' : severity === 'Medium' ? 'primary' : 'muted'}>{severity}</TonePill></td>
                      <td className="px-4 py-3 font-mono text-text-main">{range}</td>
                      <td className="px-4 py-3 text-text-muted">{examples}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3 className="pt-4 text-lg font-semibold text-text-main">Generally not eligible for recognition</h3>
            <PolicyList items={outOfRecognition} mode="no" />
          </Section>

          <Section id="disclosure" eyebrow="08 - Coordinated Disclosure" title="How Tempris handles reports over time">
            <p>Tempris follows a coordinated disclosure model. We confirm, remediate, and publicly disclose findings on an agreed timeline.</p>
            <div className="rounded-lg border border-border bg-surface">
              {disclosureTimeline.map(([day, title, body]) => (
                <div key={day} className="grid gap-3 border-b border-border px-4 py-4 last:border-b-0 md:grid-cols-[120px_1fr]">
                  <div>
                    <span className="inline-flex rounded border border-primary-500/25 bg-primary-500/10 px-3 py-1 font-mono text-xs font-semibold text-primary-400">{day}</span>
                  </div>
                  <div>
                    <h3 className="font-semibold text-text-main">{title}</h3>
                    <p className="mt-1 text-sm text-text-muted">{body}</p>
                  </div>
                </div>
              ))}
            </div>
            <Note>
              Tempris will never publish details of a finding publicly without the researcher's knowledge and will name the researcher unless anonymity is requested.
            </Note>
          </Section>

          <Section id="regulatory" eyebrow="09 - Regulatory Context" title="Singapore law and client obligations">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-border bg-surface p-5">
                <AlertTriangle className="mb-4 h-5 w-5 text-warning" />
                <h3 className="font-semibold text-text-main">Personal Data Protection Act</h3>
                <p className="mt-2 text-sm text-text-muted">If you encounter personal data belonging to Tempris clients or end users, stop immediately, do not access further, and report what you observed.</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <ClipboardCheck className="mb-4 h-5 w-5 text-primary-400" />
                <h3 className="font-semibold text-text-main">MAS TRM Guidelines</h3>
                <p className="mt-2 text-sm text-text-muted">The sandbox environment contains synthetic test data and is not connected to client production environments or real financial data.</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <ShieldAlert className="mb-4 h-5 w-5 text-primary-400" />
                <h3 className="font-semibold text-text-main">Computer Misuse and Cybersecurity Act</h3>
                <p className="mt-2 text-sm text-text-muted">This policy provides explicit authorisation for testing within scope. Testing outside scope is not authorised.</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-5">
                <Activity className="mb-4 h-5 w-5 text-primary-400" />
                <h3 className="font-semibold text-text-main">ISO/IEC 42001:2023</h3>
                <p className="mt-2 text-sm text-text-muted">AI governance risks, including model manipulation, prompt injection, and AI-driven access-control bypasses, are in scope and treated as high priority.</p>
              </div>
            </div>
          </Section>

          <Section id="hof" eyebrow="10 - Hall of Fame" title="Researchers who made Tempris more secure">
            <p>Valid security findings submitted under this programme may be acknowledged publicly here, unless the researcher requests anonymity.</p>
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full min-w-[720px] border-collapse text-left text-sm">
                <thead className="bg-surface text-[11px] uppercase tracking-[0.14em] text-text-muted">
                  <tr>
                    <th className="border-b border-border px-4 py-3">Researcher</th>
                    <th className="border-b border-border px-4 py-3">Finding Type</th>
                    <th className="border-b border-border px-4 py-3">Severity</th>
                    <th className="border-b border-border px-4 py-3">Date</th>
                    <th className="border-b border-border px-4 py-3">Recognition</th>
                  </tr>
                </thead>
                <tbody className="bg-surface/70">
                  <tr>
                    <td className="px-4 py-8 text-center font-mono text-text-muted" colSpan={5}>
                      Programme launched June 2026. First validated finding will be listed here.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </Section>

          <Section id="securitytxt" eyebrow="11 - security.txt" title="Machine-readable programme metadata">
            <p>
              The same VDP metadata is available at <a className="text-primary-400 hover:underline" href="/.well-known/security.txt">/.well-known/security.txt</a> for automated indexing by disclosure directories.
            </p>
            <pre className="overflow-x-auto rounded-lg border border-border bg-black/40 p-5 font-mono text-xs leading-6 text-primary-200">
              {securityTxt}
            </pre>
            <Note tone="warning">
              A PGP <code className="font-mono text-primary-400">Encryption:</code> entry is intentionally omitted until a real public key is published.
              Add that field after <code className="font-mono text-primary-400">/.well-known/pgp-key.txt</code> exists.
            </Note>
          </Section>

          <Section id="listing" eyebrow="12 - Directory Listings" title="Where the programme can be listed">
            <PolicyList
              items={[
                'disclose.io Programme Database: submit a pull request to diodb once this policy page is published.',
                'FireBounty: can index the programme from /.well-known/security.txt once deployed.',
                'Community announcement: publish only after Tier 2 sandbox invitations are ready.',
              ]}
            />
          </Section>

          <Section id="governance" eyebrow="13 - Policy Governance" title="How the policy is maintained">
            <PolicyList items={governance} />
            <Note tone="muted">
              This policy is governed by the laws of Singapore. It does not waive rights or remedies Tempris has under applicable law in the event of malicious or bad-faith activity.
            </Note>
          </Section>
        </div>
      </main>

      <footer className="border-t border-border bg-surface">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-8 text-sm text-text-muted md:flex-row md:items-center md:justify-between md:px-8">
          <div><span className="font-semibold text-text-main">TEMPRIS.TECH</span> - Vulnerability Disclosure Policy v1.0</div>
          <div className="flex flex-wrap gap-4">
            <a className="hover:text-primary-400" href="#top">Back to top</a>
            <a className="hover:text-primary-400" href={`mailto:${contactEmail}`}>{contactEmail}</a>
            <a className="hover:text-primary-400" href="https://disclose.io" target="_blank" rel="noreferrer">disclose.io</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
