from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional
from MobyPark.api.authentication import get_current_user, require_roles
from MobyPark.api.Models.User import User
from fastapi import Request

router = APIRouter(tags=["delete_routes"])

@router.delete("/parkinglots/{lid}", status_code=status.HTTP_200_OK)
async def delete_parking_lot(
    lid: str,
    request: Request,
    user: User = Depends(require_roles(["ADMIN"]))
) -> Dict[str, str]:
    """
    Delete a specific parking lot by ID.
    Admin only.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_parkinglots
    parking_lot = access_parkinglots.get_parking_lot(id=lid)
    if not parking_lot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parking lot not found"
        )
    
    if not access_parkinglots.delete_parking_lot(parkinglot=parking_lot):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Parkinglot still has references"
        )
    # Audit log would be handled by middleware or logging system
    return {"message": f"Parking lot {lid} deleted"}


@router.delete("/parkinglots/", status_code=status.HTTP_200_OK)
async def delete_all_parking_lots(
    request: Request,
    user: User = Depends(require_roles(["ADMIN"]))
) -> Dict[str, str]:
    """
    Delete all parking lots.
    Admin only.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import connection
    connection.cursor.execute("TRUNCATE TABLE parking_lots, parking_lots_coordinates")
    # Audit log would be handled by middleware or logging system
    return {"message": "All parking lots deleted"}


@router.delete("/reservations/{rid}", status_code=status.HTTP_200_OK)
async def delete_reservation(
    request: Request,
    rid: str,
    user: User = Depends(get_current_user)
) -> Dict[str, str]:
    """
    Delete a specific reservation.
    Users can only delete their own reservations unless they are admins.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_reservations
    from MobyPark.api.app import access_parkinglots
    reservation = access_reservations.get_reservation(id=rid)
    if not reservation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reservation not found"
        )

    if user.role != "ADMIN" and user != reservation.user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    parking_lot = reservation.parking_lot
    if parking_lot.reserved > 0:
        parking_lot.reserved -= 1
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parking lot reserved count is already zero"
        )

    access_parkinglots.update_parking_lot(parkinglot=parking_lot)
    if not access_reservations.delete_reservation(reservation=reservation):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Parkinglot still has references"
        )
    return {"status": "Deleted"}


@router.delete("/reservations/", status_code=status.HTTP_200_OK)
async def delete_all_reservations(
    request: Request,
    user: User = Depends(get_current_user)
) -> Dict[str, str]:
    """
    Delete all reservations.
    Admins can delete all reservations, users can only delete their own.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_reservations
    from MobyPark.api.app import access_parkinglots
    from MobyPark.api.app import connection
    parking_lots = access_parkinglots.get_all_parking_lots()
    
    if user.role == "ADMIN":
        connection.cursor.execute("TRUNCATE TABLE reservations")
        for parking_lot in parking_lots:
            parking_lot.reserved = 0
            access_parkinglots.update_parking_lot(parkinglot=parking_lot)
        return {"status": "All reservations deleted by admin"}
    else:
        user_reservations = access_reservations.get_reservations_by_user(user=user)
        if not user_reservations:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No reservations found for this user"
            )
            
        for reservation in user_reservations:
            parking_lot = reservation.parking_lot
            parking_lot.reserved -= 1
            access_parkinglots.update_parking_lot(parkinglot=parking_lot)
            access_reservations.delete_reservation(reservation=reservation)
            access_reservations
        
        return {"status": "All user reservations deleted"}


@router.delete("/vehicles/{vid}", status_code=status.HTTP_200_OK)
async def delete_vehicle(
    request: Request,
    vid: str,
    user: User = Depends(get_current_user)
) -> Dict[str, str]:
    """
    Delete a specific vehicle.
    Users can only delete their own vehicles unless they are admins.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_vehicles
    vehicle = access_vehicles.get_vehicle(id=vid)
    if not vehicle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vehicle not found"
        )

    if user.role != "ADMIN" and user != vehicle.user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    if not access_vehicles.delete_vehicle(vehicle=vehicle):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vehicle still has references"
        )
    return {"status": "Deleted"}


@router.delete("/sessions/{sid}", status_code=status.HTTP_200_OK)
async def delete_session(
    request: Request,
    sid: str,
    user: User = Depends(require_roles("ADMIN"))
) -> Dict[str, str]:
    """
    Delete a specific session.
    Admin only.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_sessions
    if not sid.isnumeric():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID"
        )

    session = access_sessions.get_session(id=sid)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    if not access_sessions.delete_session(session=session):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Session still has references"
        )
    
    return {"message": "Session deleted"}


@router.delete("/discount-codes/free-parking/{license_plate}", status_code=200)
async def remove_free_parking_plate(
    request: Request,
    license_plate: str,
    user: User = Depends(require_roles("ADMIN"))
):
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from ..app import access_free_parking
    try:
        success = access_free_parking.remove_free_parking_plate(license_plate)
        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"License plate {license_plate} not found in free parking whitelist"
            )
            
        return {
            "status": "success",
            "message": f"License plate {license_plate} removed from free parking whitelist"
        }
    except HTTPException:
        raise
    except Exception as e:
        # logger.log(f"Error removing free parking plate: {str(e)}", level="error")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/discount-codes/{code_id}", status_code=200)
async def delete_discount_code(
    request: Request,
    code_id: int,
    user: User = Depends(require_roles("ADMIN"))
):
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_discount_codes
    try:
        success = access_discount_codes.delete_discount_code(code_id)
        if not success:
            raise HTTPException(status_code=404, detail="Discount code not found")
            
        return {"status": "success", "message": "Discount code deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        # logger.log(f"Error deleting discount code: {str(e)}", level="error")
        raise HTTPException(status_code=500, detail="Failed to delete discount code")