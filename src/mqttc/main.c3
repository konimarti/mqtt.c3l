module mqttc;
import std::io, std::core::env;

fn int main(String[] args)
{
	if (args.len > 1 && args[1] == "--version")
	{
		io::printfn("mqttc %s", env::PROJECT_VERSION);
		return 0;
	}
	io::printn("usage: mqttc pub|sub -h HOST [-p PORT] -t TOPIC ...");
	io::printn("(publish and subscribe are not implemented yet)");
	return 0;
}
