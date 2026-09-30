package domainclass

// Organization names shared by many entries.
const (
	orgAmazon    = "Amazon"
	orgAWS       = "Amazon Web Services"
	orgApple     = "Apple"
	orgGoogle    = "Google"
	orgLG        = "LG Electronics"
	orgMeta      = "Meta"
	orgMicrosoft = "Microsoft"
	orgSamsung   = "Samsung"
)

// table is the first-party suffix table. It is curated by hand from publicly
// known facts about which company operates each domain; do not import rows
// from third-party blocklists, tracker lists or filter lists. A suffix
// matches itself and every subdomain, and the longest matching suffix wins,
// so a specific entry (fcm.googleapis.com) overrides a broader one
// (googleapis.com). Keep entries grouped by organization; order does not
// affect matching.
var table = []Entry{
	// Google: analytics and Firebase.
	{"google-analytics.com", orgGoogle, CategoryAnalytics},
	{"googletagmanager.com", orgGoogle, CategoryAnalytics},
	{"analytics.google.com", orgGoogle, CategoryAnalytics},
	{"app-measurement.com", orgGoogle, CategoryAnalytics},
	{"firebaseinstallations.googleapis.com", orgGoogle, CategoryAnalytics},
	{"firebaselogging.googleapis.com", orgGoogle, CategoryTelemetry},
	{"firebaselogging-pa.googleapis.com", orgGoogle, CategoryTelemetry},
	{"firebaseremoteconfig.googleapis.com", orgGoogle, CategoryCloudPlatform},
	{"firebaseio.com", orgGoogle, CategoryCloudPlatform},
	{"crashlytics.com", orgGoogle, CategoryCrashReporting},
	{"crashlyticsreports-pa.googleapis.com", orgGoogle, CategoryCrashReporting},
	// Google: push (Firebase Cloud Messaging).
	{"fcm.googleapis.com", orgGoogle, CategoryPush},
	{"mtalk.google.com", orgGoogle, CategoryPush},
	// Google: advertising.
	{"doubleclick.net", orgGoogle, CategoryAdvertising},
	{"googleads.g.doubleclick.net", orgGoogle, CategoryAdvertising},
	{"googlesyndication.com", orgGoogle, CategoryAdvertising},
	{"googleadservices.com", orgGoogle, CategoryAdvertising},
	{"adservice.google.com", orgGoogle, CategoryAdvertising},
	{"admob.com", orgGoogle, CategoryAdvertising},
	{"imasdk.googleapis.com", orgGoogle, CategoryAdvertising},
	// Google: platform services, CDN and cloud.
	{"google.com", orgGoogle, CategoryOSServices},
	{"android.com", orgGoogle, CategoryOSServices},
	{"gvt1.com", orgGoogle, CategoryOSServices},
	{"gvt2.com", orgGoogle, CategoryOSServices},
	{"connectivitycheck.gstatic.com", orgGoogle, CategoryOSServices},
	{"gstatic.com", orgGoogle, CategoryCDN},
	{"googleapis.com", orgGoogle, CategoryCloudPlatform},
	{"googleusercontent.com", orgGoogle, CategoryCloudPlatform},
	{"appspot.com", orgGoogle, CategoryCloudPlatform},
	{"cloudfunctions.net", orgGoogle, CategoryCloudPlatform},
	{"run.app", orgGoogle, CategoryCloudPlatform},
	// Google: YouTube and Nest.
	{"youtube.com", orgGoogle, CategoryStreaming},
	{"googlevideo.com", orgGoogle, CategoryStreaming},
	{"ytimg.com", orgGoogle, CategoryStreaming},
	{"nest.com", orgGoogle, CategoryIoTCloud},

	// Apple.
	{"apple.com", orgApple, CategoryOSServices},
	{"gs.apple.com", orgApple, CategoryOSServices},
	{"mesu.apple.com", orgApple, CategoryOSServices},
	{"icloud.com", orgApple, CategoryOSServices},
	{"push.apple.com", orgApple, CategoryPush},
	{"iadsdk.apple.com", orgApple, CategoryAdvertising},
	{"mzstatic.com", orgApple, CategoryCDN},
	{"aaplimg.com", orgApple, CategoryCDN},
	{"apple-dns.net", orgApple, CategoryCDN},
	{"cdn-apple.com", orgApple, CategoryCDN},

	// Microsoft: Windows, telemetry and push.
	{"microsoft.com", orgMicrosoft, CategoryOSServices},
	{"windowsupdate.com", orgMicrosoft, CategoryOSServices},
	{"msftconnecttest.com", orgMicrosoft, CategoryOSServices},
	{"live.com", orgMicrosoft, CategoryOSServices},
	{"events.data.microsoft.com", orgMicrosoft, CategoryTelemetry},
	{"vortex.data.microsoft.com", orgMicrosoft, CategoryTelemetry},
	{"settings-win.data.microsoft.com", orgMicrosoft, CategoryTelemetry},
	{"telemetry.microsoft.com", orgMicrosoft, CategoryTelemetry},
	{"watson.telemetry.microsoft.com", orgMicrosoft, CategoryCrashReporting},
	{"notify.windows.com", orgMicrosoft, CategoryPush},
	{"appcenter.ms", orgMicrosoft, CategoryAnalytics},
	{"adnxs.com", orgMicrosoft, CategoryAdvertising},
	// Microsoft: Azure.
	{"azure.com", orgMicrosoft, CategoryCloudPlatform},
	{"azurewebsites.net", orgMicrosoft, CategoryCloudPlatform},
	{"windows.net", orgMicrosoft, CategoryCloudPlatform},
	{"cloudapp.net", orgMicrosoft, CategoryCloudPlatform},
	{"azureedge.net", orgMicrosoft, CategoryCDN},
	{"azure-devices.net", orgMicrosoft, CategoryIoTCloud},
	{"azure-devices-provisioning.net", orgMicrosoft, CategoryIoTCloud},

	// Amazon: devices, Alexa, advertising and video.
	{"amazon.com", orgAmazon, CategoryOSServices},
	{"a2z.com", orgAmazon, CategoryOSServices},
	{"device-metrics-us.amazon.com", orgAmazon, CategoryTelemetry},
	{"device-metrics-us-2.amazon.com", orgAmazon, CategoryTelemetry},
	{"alexa.amazon.com", orgAmazon, CategoryIoTCloud},
	{"avs-alexa-na.amazon.com", orgAmazon, CategoryIoTCloud},
	{"amazonalexa.com", orgAmazon, CategoryIoTCloud},
	{"ring.com", orgAmazon, CategoryIoTCloud},
	{"amazon-adsystem.com", orgAmazon, CategoryAdvertising},
	{"media-amazon.com", orgAmazon, CategoryCDN},
	{"primevideo.com", orgAmazon, CategoryStreaming},
	{"amazonvideo.com", orgAmazon, CategoryStreaming},
	{"twitch.tv", orgAmazon, CategoryStreaming},

	// Amazon Web Services. AWS IoT Core endpoints look like
	// <id>-ats.iot.<region>.amazonaws.com, so each common region is listed.
	{"amazonaws.com", orgAWS, CategoryCloudPlatform},
	{"amazonaws.com.cn", orgAWS, CategoryCloudPlatform},
	{"aws.amazon.com", orgAWS, CategoryCloudPlatform},
	{"cloudfront.net", orgAWS, CategoryCDN},
	{"iot.us-east-1.amazonaws.com", orgAWS, CategoryIoTCloud},
	{"iot.us-east-2.amazonaws.com", orgAWS, CategoryIoTCloud},
	{"iot.us-west-2.amazonaws.com", orgAWS, CategoryIoTCloud},
	{"iot.eu-west-1.amazonaws.com", orgAWS, CategoryIoTCloud},
	{"iot.eu-central-1.amazonaws.com", orgAWS, CategoryIoTCloud},
	{"iot.ap-southeast-1.amazonaws.com", orgAWS, CategoryIoTCloud},
	{"iot.ap-northeast-1.amazonaws.com", orgAWS, CategoryIoTCloud},
	{"iot.cn-north-1.amazonaws.com.cn", orgAWS, CategoryIoTCloud},

	// Meta.
	{"facebook.net", orgMeta, CategoryAdvertising},
	{"graph.facebook.com", orgMeta, CategoryAdvertising},
	{"an.facebook.com", orgMeta, CategoryAdvertising},
	{"fbcdn.net", orgMeta, CategoryCDN},

	// Samsung: TV and phone services, ACR, advertising and SmartThings.
	{"samsung.com", orgSamsung, CategoryOSServices},
	{"samsungapps.com", orgSamsung, CategoryOSServices},
	{"samsungcloud.com", orgSamsung, CategoryOSServices},
	{"samsungotn.net", orgSamsung, CategoryOSServices},
	{"samsungacr.com", orgSamsung, CategoryTelemetry},
	{"samsungcloudsolution.com", orgSamsung, CategoryTelemetry},
	{"samsungcloudsolution.net", orgSamsung, CategoryTelemetry},
	{"samsungqbe.com", orgSamsung, CategoryTelemetry},
	{"samsungads.com", orgSamsung, CategoryAdvertising},
	{"ads.samsung.com", orgSamsung, CategoryAdvertising},
	{"smartthings.com", orgSamsung, CategoryIoTCloud},
	{"samsungiotcloud.com", orgSamsung, CategoryIoTCloud},

	// LG Electronics: webOS TV services, ACR (including Alphonso, an LG
	// subsidiary), advertising and ThinQ.
	{"lge.com", orgLG, CategoryOSServices},
	{"lgappstv.com", orgLG, CategoryOSServices},
	{"lgtvsdp.com", orgLG, CategoryTelemetry},
	{"alphonso.tv", orgLG, CategoryTelemetry},
	{"lgsmartad.com", orgLG, CategoryAdvertising},
	{"lgthinq.com", orgLG, CategoryIoTCloud},

	// Other TV platforms and TV audience measurement.
	{"roku.com", "Roku", CategoryOSServices},
	{"logs.roku.com", "Roku", CategoryTelemetry},
	{"ads.roku.com", "Roku", CategoryAdvertising},
	{"vizio.com", "Vizio", CategoryOSServices},
	{"tvinteractive.tv", "Vizio", CategoryTelemetry},
	{"samba.tv", "Samba TV", CategoryTelemetry},
	{"playstation.net", "Sony", CategoryOSServices},
	{"imrworldwide.com", "Nielsen", CategoryAnalytics},
	{"scorecardresearch.com", "Comscore", CategoryAnalytics},
	{"conviva.com", "Conviva", CategoryAnalytics},
	{"fwmrm.net", "FreeWheel", CategoryAdvertising},

	// Advertising networks and ad verification.
	{"criteo.com", "Criteo", CategoryAdvertising},
	{"taboola.com", "Taboola", CategoryAdvertising},
	{"outbrain.com", "Outbrain", CategoryAdvertising},
	{"moatads.com", "Oracle", CategoryAdvertising},
	{"adsafeprotected.com", "Integral Ad Science", CategoryAdvertising},
	{"doubleverify.com", "DoubleVerify", CategoryAdvertising},

	// Mobile advertising SDKs.
	{"unity3d.com", "Unity Technologies", CategoryAnalytics},
	{"unityads.unity3d.com", "Unity Technologies", CategoryAdvertising},
	{"supersonicads.com", "ironSource", CategoryAdvertising},
	{"applovin.com", "AppLovin", CategoryAdvertising},
	{"applvn.com", "AppLovin", CategoryAdvertising},
	{"vungle.com", "Liftoff", CategoryAdvertising},
	{"inmobi.com", "InMobi", CategoryAdvertising},
	{"chartboost.com", "Chartboost", CategoryAdvertising},
	{"adcolony.com", "Digital Turbine", CategoryAdvertising},

	// Mobile measurement, attribution and product analytics SDKs.
	{"appsflyer.com", "AppsFlyer", CategoryAnalytics},
	{"appsflyersdk.com", "AppsFlyer", CategoryAnalytics},
	{"onelink.me", "AppsFlyer", CategoryAnalytics},
	{"adjust.com", "Adjust", CategoryAnalytics},
	{"adjust.io", "Adjust", CategoryAnalytics},
	{"adj.st", "Adjust", CategoryAnalytics},
	{"branch.io", "Branch", CategoryAnalytics},
	{"app.link", "Branch", CategoryAnalytics},
	{"kochava.com", "Kochava", CategoryAnalytics},
	{"amplitude.com", "Amplitude", CategoryAnalytics},
	{"mixpanel.com", "Mixpanel", CategoryAnalytics},
	{"mxpnl.com", "Mixpanel", CategoryAnalytics},
	{"segment.io", "Segment", CategoryAnalytics},
	{"segment.com", "Segment", CategoryAnalytics},
	{"braze.com", "Braze", CategoryAnalytics},
	{"braze.eu", "Braze", CategoryAnalytics},
	{"appboy.com", "Braze", CategoryAnalytics},
	{"flurry.com", "Flurry", CategoryAnalytics},
	{"hotjar.com", "Hotjar", CategoryAnalytics},
	{"heapanalytics.com", "Heap", CategoryAnalytics},
	{"umeng.com", "Alibaba", CategoryAnalytics},

	// Application performance monitoring.
	{"nr-data.net", "New Relic", CategoryTelemetry},
	{"newrelic.com", "New Relic", CategoryTelemetry},
	{"datadoghq.com", "Datadog", CategoryTelemetry},
	{"browser-intake-datadoghq.com", "Datadog", CategoryTelemetry},

	// Crash reporting.
	{"sentry.io", "Sentry", CategoryCrashReporting},
	{"ingest.sentry.io", "Sentry", CategoryCrashReporting},
	{"bugsnag.com", "Bugsnag", CategoryCrashReporting},
	{"sessions.bugsnag.com", "Bugsnag", CategoryCrashReporting},
	{"notify.bugsnag.com", "Bugsnag", CategoryCrashReporting},
	{"instabug.com", "Instabug", CategoryCrashReporting},
	{"embrace.io", "Embrace", CategoryCrashReporting},
	{"bugly.qq.com", "Tencent", CategoryCrashReporting},

	// Push messaging services.
	{"onesignal.com", "OneSignal", CategoryPush},
	{"pusher.com", "Pusher", CategoryPush},
	{"pubnub.com", "PubNub", CategoryPush},
	{"igexin.com", "Getui", CategoryPush},
	{"jpush.cn", "Aurora Mobile", CategoryPush},

	// Streaming services.
	{"netflix.com", "Netflix", CategoryStreaming},
	{"nflxvideo.net", "Netflix", CategoryStreaming},
	{"nflxso.net", "Netflix", CategoryStreaming},
	{"nflxext.com", "Netflix", CategoryStreaming},
	{"spotify.com", "Spotify", CategoryStreaming},
	{"scdn.co", "Spotify", CategoryStreaming},
	{"hulu.com", "Hulu", CategoryStreaming},
	{"disneyplus.com", "Disney", CategoryStreaming},
	{"dssott.com", "Disney", CategoryStreaming},
	{"plex.tv", "Plex", CategoryStreaming},
	{"max.com", "Warner Bros. Discovery", CategoryStreaming},
	{"paramountplus.com", "Paramount", CategoryStreaming},
	{"pluto.tv", "Pluto TV", CategoryStreaming},

	// Content delivery networks.
	{"akamai.net", "Akamai", CategoryCDN},
	{"akamaiedge.net", "Akamai", CategoryCDN},
	{"akamaihd.net", "Akamai", CategoryCDN},
	{"akamaized.net", "Akamai", CategoryCDN},
	{"edgekey.net", "Akamai", CategoryCDN},
	{"edgesuite.net", "Akamai", CategoryCDN},
	{"fastly.net", "Fastly", CategoryCDN},
	{"fastlylb.net", "Fastly", CategoryCDN},
	{"fastly.com", "Fastly", CategoryCDN},
	{"cloudflare.com", "Cloudflare", CategoryCDN},
	{"cloudflare.net", "Cloudflare", CategoryCDN},
	{"cloudflare-dns.com", "Cloudflare", CategoryCDN},
	{"jsdelivr.net", "jsDelivr", CategoryCDN},
	{"edgecastcdn.net", "Edgio", CategoryCDN},
	{"llnwd.net", "Edgio", CategoryCDN},

	// Other cloud platforms.
	{"digitaloceanspaces.com", "DigitalOcean", CategoryCloudPlatform},
	{"herokuapp.com", "Heroku", CategoryCloudPlatform},
	{"oraclecloud.com", "Oracle", CategoryCloudPlatform},
	{"aliyuncs.com", "Alibaba", CategoryCloudPlatform},
	{"tencentcloudapi.com", "Tencent", CategoryCloudPlatform},

	// IoT and smart-home clouds.
	{"tuya.com", "Tuya", CategoryIoTCloud},
	{"tuyaus.com", "Tuya", CategoryIoTCloud},
	{"tuyaeu.com", "Tuya", CategoryIoTCloud},
	{"tuyacn.com", "Tuya", CategoryIoTCloud},
	{"tuyain.com", "Tuya", CategoryIoTCloud},
	{"espressif.com", "Espressif Systems", CategoryIoTCloud},
	{"espressif.cn", "Espressif Systems", CategoryIoTCloud},
	{"xiaomi.com", "Xiaomi", CategoryIoTCloud},
	{"xiaomi.net", "Xiaomi", CategoryIoTCloud},
	{"mi.com", "Xiaomi", CategoryIoTCloud},
	{"miui.com", "Xiaomi", CategoryOSServices},
	{"meethue.com", "Signify", CategoryIoTCloud},
	{"wyze.com", "Wyze", CategoryIoTCloud},
	{"wyzecam.com", "Wyze", CategoryIoTCloud},
	{"tplinkcloud.com", "TP-Link", CategoryIoTCloud},
	{"tplinknbu.com", "TP-Link", CategoryIoTCloud},
	{"ezvizlife.com", "EZVIZ", CategoryIoTCloud},
	{"hik-connect.com", "Hikvision", CategoryIoTCloud},
	{"arlo.com", "Arlo", CategoryIoTCloud},
	{"arlo.netgear.com", "Arlo", CategoryIoTCloud},
	{"ecobee.com", "ecobee", CategoryIoTCloud},
	{"particle.io", "Particle", CategoryIoTCloud},
	{"blynk.cloud", "Blynk", CategoryIoTCloud},
	{"shelly.cloud", "Shelly Group", CategoryIoTCloud},
	{"meross.com", "Meross", CategoryIoTCloud},
	{"govee.com", "Govee", CategoryIoTCloud},
	{"irobotapi.com", "iRobot", CategoryIoTCloud},
	{"sonos.com", "Sonos", CategoryIoTCloud},
	{"ibroadlink.com", "Broadlink", CategoryIoTCloud},
	{"coolkit.cc", "CoolKit", CategoryIoTCloud},
	{"coolkit.cn", "CoolKit", CategoryIoTCloud},

	// General operating-system infrastructure.
	{"ubuntu.com", "Canonical", CategoryOSServices},
	{"pool.ntp.org", "NTP Pool Project", CategoryOSServices},
}
