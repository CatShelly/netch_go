export namespace model {
	
	export class UISettings {
	    autoImportLegacy: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UISettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.autoImportLegacy = source["autoImportLegacy"];
	    }
	}
	export class DNSSettings {
	    enabled: boolean;
	    listen: string;
	    domesticUpstream: string;
	    proxyUpstream: string;
	    ruleFile: string;
	    applySystemDns: boolean;
	    managedAdapters: string[];
	    restoreOnStop: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DNSSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.listen = source["listen"];
	        this.domesticUpstream = source["domesticUpstream"];
	        this.proxyUpstream = source["proxyUpstream"];
	        this.ruleFile = source["ruleFile"];
	        this.applySystemDns = source["applySystemDns"];
	        this.managedAdapters = source["managedAdapters"];
	        this.restoreOnStop = source["restoreOnStop"];
	    }
	}
	export class SelectionState {
	    serverId: string;
	    ruleSetId: string;
	
	    static createFrom(source: any = {}) {
	        return new SelectionState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.serverId = source["serverId"];
	        this.ruleSetId = source["ruleSetId"];
	    }
	}
	export class ProxyOptions {
	    filterLoopback: boolean;
	    filterIntranet: boolean;
	    filterParent: boolean;
	    filterICMP: boolean;
	    filterTCP: boolean;
	    filterUDP: boolean;
	    filterDNS: boolean;
	    handleOnlyDns: boolean;
	    dnsProxy: boolean;
	    dnsDomainOnly: boolean;
	    remoteDns: string;
	    icmpDelay: number;
	
	    static createFrom(source: any = {}) {
	        return new ProxyOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filterLoopback = source["filterLoopback"];
	        this.filterIntranet = source["filterIntranet"];
	        this.filterParent = source["filterParent"];
	        this.filterICMP = source["filterICMP"];
	        this.filterTCP = source["filterTCP"];
	        this.filterUDP = source["filterUDP"];
	        this.filterDNS = source["filterDNS"];
	        this.handleOnlyDns = source["handleOnlyDns"];
	        this.dnsProxy = source["dnsProxy"];
	        this.dnsDomainOnly = source["dnsDomainOnly"];
	        this.remoteDns = source["remoteDns"];
	        this.icmpDelay = source["icmpDelay"];
	    }
	}
	export class RuleSet {
	    id: string;
	    name: string;
	    description: string;
	    source: string;
	    sourcePath: string;
	    tag: string;
	    include: string[];
	    exclude: string[];
	    domainRules: string[];
	    proxy: ProxyOptions;
	    readOnly: boolean;
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new RuleSet(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.source = source["source"];
	        this.sourcePath = source["sourcePath"];
	        this.tag = source["tag"];
	        this.include = source["include"];
	        this.exclude = source["exclude"];
	        this.domainRules = source["domainRules"];
	        this.proxy = this.convertValues(source["proxy"], ProxyOptions);
	        this.readOnly = source["readOnly"];
	        this.updatedAt = source["updatedAt"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SocksServer {
	    id: string;
	    name: string;
	    group: string;
	    host: string;
	    port: number;
	    username: string;
	    password: string;
	    version: string;
	    remoteHost: string;
	    notes: string;
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new SocksServer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.group = source["group"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.version = source["version"];
	        this.remoteHost = source["remoteHost"];
	        this.notes = source["notes"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class AppConfig {
	    servers: SocksServer[];
	    customRuleSets: RuleSet[];
	    selection: SelectionState;
	    proxy: ProxyOptions;
	    dns: DNSSettings;
	    ui: UISettings;
	
	    static createFrom(source: any = {}) {
	        return new AppConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.servers = this.convertValues(source["servers"], SocksServer);
	        this.customRuleSets = this.convertValues(source["customRuleSets"], RuleSet);
	        this.selection = this.convertValues(source["selection"], SelectionState);
	        this.proxy = this.convertValues(source["proxy"], ProxyOptions);
	        this.dns = this.convertValues(source["dns"], DNSSettings);
	        this.ui = this.convertValues(source["ui"], UISettings);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AssetCheck {
	    name: string;
	    path: string;
	    status: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new AssetCheck(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.status = source["status"];
	        this.message = source["message"];
	    }
	}
	export class LegacyDiscovery {
	    settingsPath: string;
	    rulesPath: string;
	    modeFiles: number;
	
	    static createFrom(source: any = {}) {
	        return new LegacyDiscovery(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.settingsPath = source["settingsPath"];
	        this.rulesPath = source["rulesPath"];
	        this.modeFiles = source["modeFiles"];
	    }
	}
	export class LogEntry {
	    time: string;
	    level: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new LogEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.level = source["level"];
	        this.message = source["message"];
	    }
	}
	export class DNSCaptureState {
	    enabled: boolean;
	    channelEnabled: boolean;
	    capturing: boolean;
	    message: string;
	    domains: string[];
	
	    static createFrom(source: any = {}) {
	        return new DNSCaptureState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.channelEnabled = source["channelEnabled"];
	        this.capturing = source["capturing"];
	        this.message = source["message"];
	        this.domains = source["domains"];
	    }
	}
	export class SessionStatus {
	    running: boolean;
	    proxyRunning: boolean;
	    dnsRunning: boolean;
	    startedAt: string;
	    message: string;
	    missingAssets: string[];
	    warnings: string[];
	
	    static createFrom(source: any = {}) {
	        return new SessionStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.proxyRunning = source["proxyRunning"];
	        this.dnsRunning = source["dnsRunning"];
	        this.startedAt = source["startedAt"];
	        this.message = source["message"];
	        this.missingAssets = source["missingAssets"];
	        this.warnings = source["warnings"];
	    }
	}
	export class NetworkAdapter {
	    alias: string;
	    description: string;
	    status: string;
	    ipv4: string[];
	
	    static createFrom(source: any = {}) {
	        return new NetworkAdapter(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.alias = source["alias"];
	        this.description = source["description"];
	        this.status = source["status"];
	        this.ipv4 = source["ipv4"];
	    }
	}
	export class BootstrapState {
	    config: AppConfig;
	    ruleSets: RuleSet[];
	    adapters: NetworkAdapter[];
	    assets: AssetCheck[];
	    session: SessionStatus;
	    dnsWatch: DNSCaptureState;
	    logs: LogEntry[];
	    legacy: LegacyDiscovery;
	
	    static createFrom(source: any = {}) {
	        return new BootstrapState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.config = this.convertValues(source["config"], AppConfig);
	        this.ruleSets = this.convertValues(source["ruleSets"], RuleSet);
	        this.adapters = this.convertValues(source["adapters"], NetworkAdapter);
	        this.assets = this.convertValues(source["assets"], AssetCheck);
	        this.session = this.convertValues(source["session"], SessionStatus);
	        this.dnsWatch = this.convertValues(source["dnsWatch"], DNSCaptureState);
	        this.logs = this.convertValues(source["logs"], LogEntry);
	        this.legacy = this.convertValues(source["legacy"], LegacyDiscovery);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	
	
	
	
	

}

