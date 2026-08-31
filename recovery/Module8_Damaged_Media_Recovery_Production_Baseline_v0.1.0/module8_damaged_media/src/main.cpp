#include "media/source.hpp"
#include "media/imager.hpp"
#include "media/strategy.hpp"
#include "media/json.hpp"
#include <fstream>
#include <iostream>
int main(int argc,char**argv){std::string src,dst,map,out;auto p=media::production_policy();for(int i=1;i<argc;i++){std::string a=argv[i];if(a=="--source"&&i+1<argc)src=argv[++i];else if(a=="--output"&&i+1<argc)dst=argv[++i];else if(a=="--map"&&i+1<argc)map=argv[++i];else if(a=="--report"&&i+1<argc)out=argv[++i];else if(a=="--block-sectors"&&i+1<argc)p.block_sectors=std::stoul(argv[++i]);else if(a=="--retries"&&i+1<argc)p.retries=std::stoul(argv[++i]);else{std::cerr<<"usage: mediaimager --source input --output image --map map [--block-sectors N --retries N --report json]\n";return 2;}}if(src.empty()||dst.empty()||map.empty()){std::cerr<<"source/output/map required\n";return 2;}if(src==dst){std::cerr<<"refusing source==destination\n";return 3;}std::string e;auto s=media::open_source(src,e);if(!s){std::cerr<<e<<"\n";return 3;}auto r=media::image(*s,dst,map,p);auto j=media::json(r);if(out.empty())std::cout<<j<<"\n";else{std::ofstream f(out);f<<j;}return r.status=="complete"?0:1;}
