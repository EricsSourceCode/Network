// Copyright Eric Chauvin 2023.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once


#include "../CppBase/BasicTypes.h"


class Results
  {
  private:

  public:
  // An Alert can be a result, but Alerts
  // are all Uint8 size.  So they can go
  // up to 255.

  static const Uint32 AlertTop = 256;

  static const Uint32 Done = 257;
  static const Uint32 Continue = 258;

  };
