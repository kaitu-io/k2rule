package porn

// pornKeywords contains strong keywords - platform brands and unambiguous terms
var pornKeywords = []string{
	// Platform brands
	"porn", "pornhub", "xvideo", "xnxx", "hentai", "chaturbate",
	"onlyfans", "redtube", "youporn", "spankbang", "xhamster",
	"brazzers", "bangbros", "porntrex", "porntube", "pornstar",
	"livejasmin", "bongacams", "stripchat", "manyvids",
}

// pornTerminology contains porn industry terminology - explicit terms
var pornTerminology = []string{
	// Body parts
	"pussy", "cock", "dick", "tits", "boobs",
	// Activities
	"fuck", "fucking", "anal", "gangbang", "blowjob", "cumshot",
	// Genres/fetishes
	"bdsm", "fetish", "bondage", "hardcore",
	// Demographics/categories
	"milf", "teen", "teens", "mature", "amateur", "asian", "ebony",
	// Orientation
	"gay", "lesbian", "shemale",
	// Roles
	"escort", "slut",
	// Platform/format
	"webcam", "livecam",
	// Descriptive
	"nude", "naked", "dirty", "sexy", "erotic",
	// Multi-language
	"porno", "sexe", "jav",
}

// pornCompounds contains compound terms - multi-word combinations
var pornCompounds = []string{
	"sexcam", "freeporn", "livesex", "porntube", "xxxporn",
	"sextube", "xxxtube", "hotsex", "sexporn", "xxxsex",
	"pornsite", "pornsex", "hotporn", "freesex", "freecam",
	"sexsite", "liveporn", "porncam", "xxxcam", "realsex",
	"sexshow", "liveshow", "hotcam", "bigass", "phatass", "niceass",
}

// verbNounPatterns contains verb+noun sequential patterns (137 patterns)
var verbNounPatterns = [][2]string{
	{"free", "porn"}, {"live", "sex"}, {"live", "cam"},
	{"free", "sex"}, {"cam", "sex"}, {"cam", "girl"},
	{"cam", "girls"}, {"live", "cams"}, {"free", "cam"},
	{"free", "xxx"}, {"chat", "sex"}, {"free", "cams"},
	{"free", "video"}, {"free", "gay"}, {"live", "porn"},
	{"free", "adult"}, {"cam", "porn"}, {"live", "girl"},
	{"cam", "babe"}, {"free", "videos"}, {"cam", "xxx"},
	{"free", "movie"}, {"free", "teen"}, {"live", "girls"},
	{"chat", "cam"}, {"live", "xxx"}, {"cam", "babes"},
	{"watch", "porn"}, {"free", "movies"}, {"free", "nude"},
	{"cam", "video"}, {"get", "sex"}, {"chat", "girl"},
	{"chat", "porn"}, {"live", "gay"}, {"free", "girl"},
	{"get", "porn"}, {"chat", "xxx"}, {"find", "sex"},
	{"chat", "gay"}, {"live", "nude"}, {"chat", "girls"},
	{"free", "shemale"}, {"meet", "sex"}, {"live", "adult"},
	{"cam", "teen"}, {"cam", "gay"}, {"free", "milf"},
	{"live", "video"}, {"chat", "cams"}, {"stream", "porn"},
	{"free", "lesbian"}, {"show", "girl"}, {"cam", "videos"},
	{"free", "teens"}, {"free", "girls"}, {"find", "porn"},
	{"download", "porn"}, {"cam", "adult"}, {"show", "sex"},
	{"get", "naked"}, {"cam", "teens"}, {"show", "cam"},
	{"live", "teen"}, {"see", "sex"}, {"show", "girls"},
	{"chat", "adult"}, {"watch", "xxx"}, {"view", "porn"},
	{"free", "anal"}, {"meet", "gay"}, {"download", "xxx"},
	{"download", "video"}, {"see", "porn"}, {"cam", "nude"},
	{"live", "babe"}, {"free", "boy"}, {"chat", "nude"},
	{"chat", "video"}, {"stream", "sex"}, {"live", "boy"},
	{"download", "sex"}, {"see", "xxx"}, {"live", "babes"},
	{"meet", "girl"}, {"find", "gay"}, {"get", "xxx"},
	{"meet", "milf"}, {"watch", "video"}, {"stream", "xxx"},
	{"cam", "trans"}, {"live", "shemale"}, {"watch", "sex"},
	{"watch", "movie"}, {"watch", "cam"}, {"live", "teens"},
	{"free", "naked"}, {"free", "babe"}, {"get", "gay"},
	{"live", "videos"}, {"meet", "girls"}, {"get", "girl"},
	{"stream", "video"}, {"chat", "babe"}, {"live", "naked"},
	{"find", "adult"}, {"find", "cam"}, {"watch", "girl"},
	{"view", "xxx"}, {"get", "cam"}, {"view", "sex"},
	{"show", "xxx"}, {"free", "boys"}, {"free", "babes"},
	{"find", "girl"}, {"show", "porn"}, {"live", "trans"},
	{"live", "milf"}, {"chat", "babes"}, {"cam", "shemale"},
	{"cam", "milf"}, {"watch", "adult"}, {"see", "cam"},
	{"see", "girl"}, {"live", "lesbian"}, {"meet", "trans"},
	{"find", "cams"}, {"find", "milf"}, {"download", "videos"},
	{"watch", "gay"}, {"show", "cams"}, {"free", "trans"},
	{"free", "oral"},
}

// carefulKeywords are keywords that need more careful matching
var carefulKeywords = []string{"xxx", "sex", "adult"}

// adultTLDs contains ICANN-approved adult content TLDs
var adultTLDs = []string{"xxx", "adult", "porn", "sex"}
