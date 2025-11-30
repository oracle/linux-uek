/* Copyright (c) 2020 Arista Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _LINUX_DRIVER_SCD_ATTRS_H_
#define _LINUX_DRIVER_SCD_ATTRS_H_

#define __ATTR_NAME_PTR(_name, _mode, _show, _store) {  \
   .attr = { .name = _name,                             \
             .mode = VERIFY_OCTAL_PERMISSIONS(_mode) }, \
   .show = _show,                                       \
   .store = _store                                      \
}

#define __SENSOR_ATTR_NAME_PTR(_name, _mode, _show, _store, _index)   \
   { .dev_attr = __ATTR_NAME_PTR(_name, _mode, _show, _store),        \
     .index = _index                                                  \
   }

#endif /* !_LINUX_DRIVER_SCD_ATTRS_H_ */
