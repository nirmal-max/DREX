#include "media/map.hpp"
#include <fstream>
#include <cstdio>
namespace media {
bool save_map(const Map&m,const std::string&p){auto tmp=p+".tmp";{std::ofstream f(tmp,std::ios::binary|std::ios::trunc);if(!f)return false;f<<"DMAP1 "<<m.sector_size<<" "<<m.sector_count<<"\n";for(auto&s:m.sectors)f<<(int)s.state<<" "<<s.attempts<<" "<<s.last_error<<"\n";if(!f)return false;}std::remove(p.c_str());return std::rename(tmp.c_str(),p.c_str())==0;}
bool load_map(const std::string&p,Map&m){std::ifstream f(p);std::string magic;if(!(f>>magic>>m.sector_size>>m.sector_count)||magic!="DMAP1")return false;m.sectors.resize((size_t)m.sector_count);for(auto&s:m.sectors){int x;if(!(f>>x>>s.attempts>>s.last_error))return false;s.state=(State)x;}return true;}
}
