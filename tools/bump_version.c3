module bump_version;
import std::io, std::io::file;

// Sets the version of the library in project.json and in `const String VERSION` of mqtt.c3 (the test
// version_matches_project_json keeps them equal). Run from the repository root:
//   c3c compile-run tools/bump_version.c3 -- 0.2.0
// Exit 1 and nothing written unless the argument is MAJOR.MINOR.PATCH and each pattern occurs exactly once.

const String PROJECT = "project.json";
const String MAIN = "mqtt.c3";

fn bool semver(String v)
{
	int parts;
	bool digits;
	foreach (c : v)
	{
		if (c >= '0' && c <= '9')
		{
			digits = true;
		}
		else if (c == '.' && digits)
		{
			parts++;
			digits = false;
		}
		else
		{
			return false;
		}
	}
	return parts == 2 && digits;
}

fn sz find(String text, String needle, sz from)
{
	for (sz i = from; i + needle.len <= text.len; i++)
	{
		if (text[i:needle.len] == needle) return i;
	}
	return -1;
}

// Text with the version after `marker` replaced; `line` gets the changed line. Faults unless the marker occurs once.
fn String? replace_once(String text, String marker, String version, String* line)
{
	sz at = find(text, marker, 0);
	if (at < 0 || find(text, marker, at + 1) >= 0) return io::INVALID_FORMAT~;
	sz start = at + marker.len;
	sz end = find(text, "\"", start);
	if (end < 0) return io::INVALID_FORMAT~;
	sz from = at;
	while (from > 0 && text[from - 1] != '\n') from--;
	sz to = end;
	while (to < text.len && text[to] != '\n') to++;
	String result = string::format(tmem, "%s%s%s", text[:start], version, text[end..]);
	*line = string::format(tmem, "%s%s%s", text[from:start - from], version, text[end:to - end]);
	return result;
}

fn int main(String[] argv)
{
	if (argv.len != 2 || !semver(argv[1]))
	{
		io::eprintn("usage: c3c compile-run tools/bump_version.c3 -- MAJOR.MINOR.PATCH");
		return 1;
	}
	String version = argv[1];
	String? project = (String)file::load_temp(PROJECT);
	String? main_file = (String)file::load_temp(MAIN);
	if (catch project)
	{
		io::eprintn("bump_version: run it from the repository root (project.json and mqtt.c3 must be there)");
		return 1;
	}
	if (catch main_file)
	{
		io::eprintn("bump_version: run it from the repository root (project.json and mqtt.c3 must be there)");
		return 1;
	}
	String line_a;
	String line_b;
	String? new_project = replace_once(project, "\"version\": \"", version, &line_a);
	String? new_main = replace_once(main_file, "const String VERSION = \"", version, &line_b);
	if (catch new_project)
	{
		io::eprintn("bump_version: project.json needs exactly one \"version\": \"...\"; nothing written");
		return 1;
	}
	if (catch new_main)
	{
		io::eprintn("bump_version: mqtt.c3 needs exactly one const String VERSION = \"...\"; nothing written");
		return 1;
	}
	if (catch file::save(PROJECT, new_project))
	{
		io::eprintn("bump_version: cannot write project.json");
		return 1;
	}
	if (catch file::save(MAIN, new_main))
	{
		io::eprintn("bump_version: cannot write mqtt.c3 (project.json was changed already)");
		return 1;
	}
	io::printfn("%s: %s", PROJECT, line_a.trim());
	io::printfn("%s: %s", MAIN, line_b.trim());
	return 0;
}
