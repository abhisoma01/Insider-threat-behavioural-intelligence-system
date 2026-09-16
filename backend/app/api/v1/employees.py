from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc, asc
from app.database import get_db
from app.models.employee import Employee
from app.models.user import User
from app.api.v1.auth import require_roles
from app.schemas.employee import (
    EmployeeRead,
    EmployeeListResponse,
    ContainmentResponse,
    EmployeeCreate
)

router = APIRouter(prefix="/employees", tags=["Monitored Identities"])


@router.get("", response_model=EmployeeListResponse)
def list_employees(
    search: Optional[str] = None,
    department: Optional[str] = None,
    risk_level: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    sort_by: str = Query("score", pattern="^(score|name|id|department|risk_level)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Retrieves a paginated, filterable directory of monitored corporate identities."""
    query = db.query(Employee)

    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                Employee.name.ilike(s),
                Employee.id.ilike(s),
                Employee.department.ilike(s),
                Employee.role.ilike(s),
                Employee.email.ilike(s)
            )
        )

    if department and department != "All":
        query = query.filter(Employee.department == department)

    if risk_level and risk_level != "All":
        query = query.filter(Employee.risk_level == risk_level)

    if status_filter and status_filter != "All":
        query = query.filter(Employee.status == status_filter)

    total = query.count()

    # Sorting
    col = getattr(Employee, sort_by)
    if order == "desc":
        query = query.order_by(desc(col))
    else:
        query = query.order_by(asc(col))

    # Pagination
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return EmployeeListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[EmployeeRead.model_validate(emp) for emp in items]
    )


@router.post("", response_model=EmployeeRead, status_code=status.HTTP_201_CREATED)
def create_monitored_employee(
    payload: EmployeeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrator", "Security Manager", "SOC Engineer"]))
):
    """Enrolls a new monitored identity into the threat intelligence platform."""
    # Compute auto-increment identity ID if not given
    all_emp_ids = [int(emp.id) for emp in db.query(Employee.id).all() if emp.id.isdigit()]
    next_id = str(max(all_emp_ids, default=100) + 1)

    initials = "".join([part[0].upper() for part in payload.name.split()[:2]]) or "ID"
    email = payload.email or f"{payload.name.lower().replace(' ', '.')}@threat.ai"
    dept_code = payload.department[:3].upper() if payload.department else "SEC"
    workstation = payload.workstation or f"WS-{dept_code}-{next_id}"
    ip_address = payload.ip_address or f"192.168.{int(next_id) % 8 + 1}.{int(next_id) % 200 + 10}"

    new_emp = Employee(
        id=next_id,
        name=payload.name,
        department=payload.department,
        role=payload.role,
        status=payload.status or "Active",
        email=email,
        workstation=workstation,
        ip_address=ip_address,
        location=payload.location or "Headquarters / Remote",
        risk_level=payload.risk_level or "Low",
        score=payload.score if payload.score is not None else 15,
        last_activity="Enrolled in continuous behavioral monitoring",
        seen="Just now",
        avatar_bg="#e8f0fe",
        avatar_color="#1a73e8",
        initial=initials,
        details=payload.details or f"Identity enrolled by {current_user.name} ({current_user.role}).",
        behavioral_indicators=["Baseline Profile Initialized", "Standard Access Envelope"],
        risk_factors=[{"name": "Baseline Verification", "score": 10, "weight": "Low"}],
        security_events=[]
    )

    db.add(new_emp)
    db.commit()
    db.refresh(new_emp)

    # Initialize behavioral baseline profile
    from app.services.profiling_engine import recalculate_employee_baseline
    try:
        recalculate_employee_baseline(db, new_emp.id)
    except Exception as e:
        print(f"Baseline init warning for new employee {new_emp.id}: {e}")

    # Emit system notification
    from app.api.v1.notifications import create_system_notification
    create_system_notification(
        db=db,
        title=f"New Identity Enrolled: {new_emp.name}",
        message=f"{new_emp.name} ({new_emp.role}, {new_emp.department}) enrolled in threat monitoring by {current_user.name}.",
        severity="Low",
        notif_type="system",
        employee_id=new_emp.id,
        link=f"/employees/{new_emp.id}"
    )

    return EmployeeRead.model_validate(new_emp)


@router.get("/{employee_id}", response_model=EmployeeRead)
def get_employee(employee_id: str, db: Session = Depends(get_db)):
    """Retrieves full behavioral dossier for a monitored employee."""
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity #{employee_id} not found in monitored database."
        )
    return EmployeeRead.model_validate(emp)


@router.post("/{employee_id}/lock", response_model=ContainmentResponse)
def lock_employee_account(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Security Manager", "Administrator"]))
):
    """Executes immediate isolation containment directive on the identity (Manager/Admin only)."""
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity #{employee_id} not found."
        )

    emp.status = "Locked"
    emp.risk_level = "Low"
    emp.score = 0
    emp.last_activity = f"Account isolated by {current_user.name} ({current_user.role})"
    db.commit()
    db.refresh(emp)

    from app.api.v1.notifications import create_system_notification
    create_system_notification(
        db=db,
        title=f"Containment Directive: {emp.name} Isolated",
        message=f"Account credentials isolated and active sessions revoked by {current_user.name} ({current_user.role}).",
        severity="Critical",
        notif_type="containment",
        employee_id=emp.id,
        link=f"/employees/{emp.id}"
    )

    return ContainmentResponse(
        id=emp.id,
        status=emp.status,
        score=emp.score,
        risk_level=emp.risk_level,
        message=f"Credentials for {emp.name} suspended by {current_user.role}."
    )


@router.post("/{employee_id}/reset-score", response_model=ContainmentResponse)
def reset_employee_score(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Security Manager", "Administrator"]))
):
    """Recalibrates behavioral threat score back to standard baseline (Manager/Admin only)."""
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity #{employee_id} not found."
        )

    emp.status = "Active"
    emp.risk_level = "Low"
    emp.score = 15
    emp.last_activity = f"Risk score reset by {current_user.name} ({current_user.role})"
    db.commit()
    db.refresh(emp)

    return ContainmentResponse(
        id=emp.id,
        status=emp.status,
        score=emp.score,
        risk_level=emp.risk_level,
        message=f"Threat score for {emp.name} reset to baseline."
    )


@router.post("/{employee_id}/dismiss-flag", response_model=ContainmentResponse)
def dismiss_employee_flag(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Security Manager", "Administrator"]))
):
    """Dismisses active security flag on an employee (Manager/Admin only)."""
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity #{employee_id} not found."
        )

    emp.status = "Active"
    emp.risk_level = "Low"
    emp.score = min(emp.score, 20)
    emp.last_activity = f"Security flag cleared by {current_user.name} ({current_user.role})"
    db.commit()
    db.refresh(emp)

    return ContainmentResponse(
        id=emp.id,
        status=emp.status,
        score=emp.score,
        risk_level=emp.risk_level,
        message=f"Security flag cleared for {emp.name}."
    )
