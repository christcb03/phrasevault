import AppKit
import SwiftUI

/// PVOS D226 — one destination as `pvfs-companion log list --json` gives it
/// (never its token).
struct LogDestinationRow: Decodable, Identifiable {
    var id: String { name }
    let name: String
    let type: String
    let target: String
    let privacy: String
    let min_severity: String
    let categories: [String]
    let token: String
    let enabled: Bool
    let problems: [String]
}

extension AgentController {
    var logFileURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/PVFS/companion.log")
    }

    func refreshLogDestinations() {
        let r = runCompanionCapturing(args: ["log", "list", "--json"], env: [:], stdin: nil)
        guard r.exitCode == 0, let data = r.stdout.data(using: .utf8) else {
            logError = r.stderr.isEmpty ? "Could not read the log destinations." : r.stderr
            return
        }
        do {
            logDestinations = try JSONDecoder().decode([LogDestinationRow].self, from: data)
            logError = nil
        } catch {
            logError = "Could not read the log destinations: \(error.localizedDescription)"
        }
    }

    /// `nil` when added, else why not.
    func addLogDestination(_ destination: [String: Any], token: String) -> String? {
        let req: [String: Any] = ["destination": destination, "token": token]
        guard let data = try? JSONSerialization.data(withJSONObject: req),
              let text = String(data: data, encoding: .utf8) else { return "Could not encode the destination." }
        let r = runCompanionCapturing(args: ["log", "add", "--json"], env: [:], stdin: text)
        refreshLogDestinations()
        return r.exitCode == 0 ? nil : Self.cleanError(r.stderr)
    }

    func testLogDestination(_ name: String) {
        logTestResults[name] = "Sending…"
        let r = runCompanionCapturing(args: ["log", "test", name, "--json"], env: [:], stdin: nil)
        if let data = r.stdout.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            logTestResults[name] = (obj["ok"] as? Bool == true) ? "Accepted" : "Failed: \(obj["error"] as? String ?? "?")"
        } else {
            logTestResults[name] = "Failed: \(Self.cleanError(r.stderr))"
        }
    }

    func removeLogDestination(_ name: String) {
        let r = runCompanionCapturing(args: ["log", "remove", name, "--yes", "--json"], env: [:], stdin: nil)
        if r.exitCode != 0 { logError = Self.cleanError(r.stderr) }
        logTestResults[name] = nil
        refreshLogDestinations()
    }

    /// The build the bundled companion was built from.
    func refreshCompanionVersion() {
        let r = runCompanionCapturing(args: ["--version"], env: [:], stdin: nil)
        companionVersion = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func cleanError(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.hasPrefix("pvfs-companion: ") ? String(t.dropFirst("pvfs-companion: ".count)) : t
    }
}

/// Settings → Logging: how much the agent logs, and where its records go.
struct LoggingSection: View {
    @ObservedObject var agent: AgentController
    @State private var adding = false

    var body: some View {
        Section {
            Picker("Level", selection: $agent.logLevel) {
                Text("Errors only").tag("error")
                Text("Warnings").tag("warning")
                Text("Notices").tag("notice")
                Text("Info (default)").tag("info")
                Text("Debug (verbose)").tag("debug")
            }
            if agent.logDestinations.isEmpty {
                Text("Records stay on this Mac (Details → Log file).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(agent.logDestinations) { d in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(d.name).font(.body.weight(.semibold))
                        Text("\(d.type) → \(d.target)").font(.caption.monospaced()).foregroundStyle(.secondary)
                        Spacer()
                        Button("Test") { agent.testLogDestination(d.name) }
                        Button("Remove", role: .destructive) { agent.removeLogDestination(d.name) }
                    }
                    Text("privacy \(d.privacy) · from \(d.min_severity) up · \(d.categories.isEmpty ? "all categories" : d.categories.joined(separator: ", ")) · token: \(d.token)")
                        .font(.caption).foregroundStyle(.secondary)
                    if let r = agent.logTestResults[d.name] {
                        Text(r).font(.caption).foregroundStyle(r.hasPrefix("Accepted") ? .green : (r.hasPrefix("Failed") ? .red : .secondary))
                    }
                    ForEach(d.problems, id: \.self) { p in
                        Text(p).font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            Button("Add destination…") { adding = true }
            if let e = agent.logError {
                Text(e).font(.caption).foregroundStyle(.red)
            }
        } header: {
            Text("Logging")
        } footer: {
            Text("The level applies when the agent restarts. Destinations apply within 30 seconds.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .sheet(isPresented: $adding) {
            AddDestinationSheet(agent: agent, taken: agent.logDestinations.map(\.name)) { adding = false }
        }
        .onAppear { agent.refreshLogDestinations() }
    }
}

/// The same questions as `pvfs log destinations add`, as a form.
struct AddDestinationSheet: View {
    @ObservedObject var agent: AgentController
    let taken: [String]
    let done: () -> Void

    @State private var name = "logs"
    @State private var type = "loki"
    @State private var target = ""
    @State private var transport = "tls"
    @State private var format = "rfc5424"
    @State private var index = ""
    @State private var labels = ""
    @State private var token = ""
    @State private var verify = "roots"
    @State private var caFile = ""
    @State private var pin = ""
    @State private var privacy = "minimal"
    @State private var confirmWide = false
    @State private var minSeverity = "info"
    @State private var system = true
    @State private var audit = true
    @State private var security = true
    @State private var error: String?

    private var usesAddress: Bool { type == "syslog" || (type == "gelf" && transport != "http") }
    private var usesTLS: Bool { usesAddress ? (type == "syslog" && transport == "tls") : target.lowercased().hasPrefix("https://") }
    private var placeholder: String {
        switch type {
        case "loki": return "http://192.168.1.83:3100"
        case "splunk_hec": return "https://splunk.example.com:8088"
        case "syslog": return transport == "tls" ? "siem.example.com:6514" : "siem.example.com:514"
        case "gelf": return transport == "http" ? "http://graylog.example.com:12201/gelf" : "graylog.example.com:12201"
        case "elasticsearch": return "https://elastic.example.com:9200"
        case "otlp": return "http://otel-collector.example.com:4318"
        default: return "https://collector.example.com/ingest"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Add a log destination").font(.headline).padding()
            Form {
                TextField("Name", text: $name)
                Picker("Type", selection: $type) {
                    Text("Loki").tag("loki")
                    Text("Splunk HEC").tag("splunk_hec")
                    Text("Syslog (SIEM)").tag("syslog")
                    Text("Elasticsearch / OpenSearch").tag("elasticsearch")
                    Text("OpenTelemetry (OTLP)").tag("otlp")
                    Text("Graylog (GELF)").tag("gelf")
                    Text("HTTPS JSON").tag("https_json")
                }
                .onChange(of: type) { t in
                    transport = t == "gelf" ? "udp" : "tls"
                    format = t == "https_json" ? "schema1" : "rfc5424"
                    index = t == "elasticsearch" ? "logs-pvfs-default" : ""
                }
                if type == "syslog" {
                    Picker("Transport", selection: $transport) {
                        Text("TLS").tag("tls"); Text("TCP").tag("tcp"); Text("UDP").tag("udp")
                    }
                    Picker("Format", selection: $format) {
                        Text("RFC 5424").tag("rfc5424"); Text("CEF").tag("cef"); Text("LEEF").tag("leef")
                        Text("JSON").tag("json"); Text("RFC 3164").tag("rfc3164")
                    }
                }
                if type == "gelf" {
                    Picker("Transport", selection: $transport) {
                        Text("UDP").tag("udp"); Text("TCP").tag("tcp"); Text("HTTP").tag("http")
                    }
                }
                TextField(usesAddress ? "Receiver (host:port)" : "URL", text: $target, prompt: Text(placeholder))
                if type == "https_json" {
                    Picker("Format", selection: $format) {
                        Text("PVFS's own (schema 1)").tag("schema1"); Text("ECS").tag("ecs"); Text("OCSF").tag("ocsf")
                    }
                }
                if type == "elasticsearch" || type == "splunk_hec" {
                    TextField(type == "elasticsearch" ? "Index or data stream" : "Index (blank = the token's default)", text: $index)
                }
                if type == "loki" {
                    TextField("Extra labels (name=value, …)", text: $labels, prompt: Text("env=prod"))
                }
                if !usesAddress || type == "gelf" {
                    SecureField(type == "elasticsearch" ? "API key" : (type == "splunk_hec" ? "HEC token" : "Token (if the receiver wants one)"), text: $token)
                }
                if usesTLS {
                    Picker("Check its certificate by", selection: $verify) {
                        Text("Public CAs").tag("roots"); Text("A CA file").tag("ca"); Text("Its SHA-256 (pin)").tag("pin")
                    }
                    if verify == "ca" { TextField("CA file (PEM)", text: $caFile) }
                    if verify == "pin" { TextField("SHA-256 (openssl x509 -fingerprint -sha256)", text: $pin) }
                }
                Picker("Privacy", selection: $privacy) {
                    Text("Minimal — no names, paths or emails").tag("minimal")
                    Text("Identified — names and addresses").tag("identified")
                    Text("Full — everything, paths included").tag("full")
                }
                if privacy != "minimal" {
                    Toggle(privacy == "full" ? "Send everything, file names and paths included" : "Send names, emails and addresses", isOn: $confirmWide)
                }
                Picker("Least severe to send", selection: $minSeverity) {
                    Text("Error").tag("error"); Text("Warning").tag("warning"); Text("Notice").tag("notice"); Text("Info").tag("info")
                }
                Toggle("System records", isOn: $system)
                Toggle("Audit records", isOn: $audit)
                Toggle("Security records", isOn: $security)
                if let error {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }
            .formStyle(.grouped)
            HStack {
                Button("Cancel") { done() }
                Spacer()
                Button("Add") { add() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty || target.isEmpty || (privacy != "minimal" && !confirmWide) || !(system || audit || security))
            }
            .padding()
        }
        .frame(width: 520, height: 620)
    }

    private func add() {
        if taken.contains(name) {
            error = "There is already a destination named \(name)."
            return
        }
        var d: [String: Any] = ["name": name, "type": type, "privacy": privacy, "min_severity": minSeverity]
        let t = target.trimmingCharacters(in: .whitespaces)
        if usesAddress { d["address"] = t } else { d["url"] = t }
        if type == "syslog" || type == "gelf" { d["transport"] = transport }
        if type == "syslog" || type == "https_json" { d["format"] = format }
        if (type == "elasticsearch" || type == "splunk_hec") && !index.isEmpty { d["index"] = index }
        if type == "loki" && !labels.isEmpty {
            var map: [String: String] = [:]
            for pair in labels.split(separator: ",") {
                let kv = pair.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard kv.count == 2 else {
                    error = "Label “\(pair)”: write it as name=value."
                    return
                }
                map[kv[0]] = kv[1]
            }
            d["labels"] = map
        }
        if usesTLS {
            if verify == "ca" { d["tls"] = ["ca_file": caFile] }
            if verify == "pin" { d["tls"] = ["pin_sha256": pin] }
        }
        let cats = [("system", system), ("audit", audit), ("security", security)].filter { $0.1 }.map { $0.0 }
        if cats.count < 3 { d["categories"] = cats }
        if let e = agent.addLogDestination(d, token: token) {
            error = e
        } else {
            token = ""
            done()
        }
    }
}
