// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#include "FinishedMesg.h"
#include "Alerts.h"
#include "Results.h"
#include "../CppBase/StIO.h"





Uint32 FinishedMesg::parseMsg(
                  const CharBuf& finishBuf,
                  TlsMain& tlsMain )
{
StIO::putS(
      "Parsing Finished Message." );

// Set cl or srv message?
// tlsMain.setFinishedMsg( finishBuf );
tlsMain.setNeedsWorkDone( true );

StIO::putLF();
finishBuf.showHex();
StIO::putLF();

StIO::putLF();
StIO::putS( "End of Finished Message." );

return Results::Done;
}
