from flask import Blueprint, render_template, request, current_app, g
from database import (
    CommentRepository,
    ProfileRepository,
    ApplicationEventRepository,
    SecurityEventRepository
)
from security import (
    process_security_pipeline,
    render_blocked_response,
    validate_url,
    ResponseAction
)

feature_bp = Blueprint("features", __name__)

# Sample deterministic dataset for the search feature (No external API calls)
SAMPLE_ARTICLES = [
    {
        "id": 1,
        "title": "Cross-Site Scripting (XSS) Fundamentals",
        "category": "Cybersecurity",
        "summary": "An introduction to client-side code injection vulnerabilities, contexts, and defensive mechanisms."
    },
    {
        "id": 2,
        "title": "Secure Flask Web Architecture",
        "category": "Web Development",
        "summary": "Building resilient Python applications with application factories, blueprints, and sanitized handlers."
    },
    {
        "id": 3,
        "title": "Python for Security Automation",
        "category": "Python",
        "summary": "Leveraging Python's standard library and automated testing tools for defensible software development."
    },
    {
        "id": 4,
        "title": "Computer Networking and HTTP Protocols",
        "category": "Networking",
        "summary": "Understanding request headers, response codes, and communication structures across TCP/IP."
    },
    {
        "id": 5,
        "title": "Defensive Input Validation Strategies",
        "category": "Application Security",
        "summary": "Comparing allowlists, denylists, boundary limits, and context-aware sanitization paradigms."
    },
    {
        "id": 6,
        "title": "Database Security and Prepared Statements",
        "category": "Database",
        "summary": "Protecting relational data stores against injection vulnerabilities using parameterized bindings."
    }
]


# ============================================================================
# SEARCH FEATURE
# ============================================================================

@feature_bp.route("/search", methods=["GET", "POST"])
def search():
    """
    Search route handling GET queries and POST submissions.
    Filters deterministic local sample data with input validation and length constraints.
    Analyzes input via Phase 4/5 pipeline and enforces policy responses.
    """
    query = ""
    results = []
    has_searched = False
    validation_error = None
    req_id = getattr(g, "request_id", None)

    if request.method == "POST":
        raw_query = request.form.get("query", "")
        has_searched = True

        # Phase 5 Defense Pipeline: Detect -> Policy -> Response
        result, decision = process_security_pipeline(
            field_name="query",
            raw_value=raw_query,
            endpoint="/search",
            method="POST",
            context="html_text",
            request_id=req_id
        )

        if not decision.should_continue:
            return render_blocked_response(decision)

        query = raw_query.strip()

    elif request.method == "GET" and "query" in request.args:
        raw_query = request.args.get("query", "")
        has_searched = True

        result, decision = process_security_pipeline(
            field_name="query",
            raw_value=raw_query,
            endpoint="/search",
            method="GET",
            context="html_text",
            request_id=req_id
        )

        if not decision.should_continue:
            return render_blocked_response(decision)

        query = raw_query.strip()

    if has_searched:
        if not query:
            validation_error = "Search query cannot be empty. Please enter a keyword."
            current_app.logger.info("Search requested with empty query. [req_id=%s]", req_id)
        elif len(query) > 100:
            validation_error = "Search query exceeds maximum length of 100 characters."
            current_app.logger.warning("Search query exceeds character limit. [req_id=%s]", req_id)
        else:
            q_lower = query.lower()
            results = [
                item for item in SAMPLE_ARTICLES
                if q_lower in item["title"].lower() or q_lower in item["category"].lower() or q_lower in item["summary"].lower()
            ]
            current_app.logger.info("Search executed for query: '%s' (Results: %d) [req_id=%s]", query[:30], len(results), req_id)
            ApplicationEventRepository.create(
                event_type="SEARCH_EXECUTED",
                endpoint="/search",
                request_id=req_id,
                details={"query_length": len(query), "match_count": len(results)}
            )

    return render_template(
        "search.html",
        query=query,
        results=results,
        has_searched=has_searched,
        validation_error=validation_error
    )


# ============================================================================
# COMMENT FEATURE (PERSISTENT SQLITE + XSS PREVENTION)
# ============================================================================

@feature_bp.route("/comments", methods=["GET", "POST"])
def comments():
    """
    Comment submission and display route with SQLite persistence and XSS prevention.
    Evaluates author and content fields. Blocks or rejects suspicious inputs according to policy.
    """
    validation_error = None
    success_message = None
    req_id = getattr(g, "request_id", None)

    if request.method == "POST":
        raw_author = request.form.get("author", "")
        raw_content = request.form.get("content", "")

        # Run Phase 5 Pipeline on author
        _, author_decision = process_security_pipeline(
            field_name="author",
            raw_value=raw_author,
            endpoint="/comments",
            method="POST",
            context="html_text",
            request_id=req_id
        )
        if not author_decision.should_continue:
            return render_blocked_response(author_decision)

        # Run Phase 5 Pipeline on content
        _, content_decision = process_security_pipeline(
            field_name="content",
            raw_value=raw_content,
            endpoint="/comments",
            method="POST",
            context="html_text",
            request_id=req_id
        )
        if not content_decision.should_continue:
            return render_blocked_response(content_decision)

        author = raw_author.strip()
        content = raw_content.strip()

        # Input validation
        if not author:
            validation_error = "Author name is required."
        elif len(author) > 50:
            validation_error = "Author name must not exceed 50 characters."
        elif not content:
            validation_error = "Comment message cannot be empty."
        elif len(content) > 500:
            validation_error = "Comment message must not exceed 500 characters."
        else:
            comment_id = CommentRepository.create(author, content)
            current_app.logger.info("New comment #%d saved for author: '%s' [req_id=%s]", comment_id, author[:20], req_id)
            ApplicationEventRepository.create(
                event_type="COMMENT_CREATED",
                endpoint="/comments",
                request_id=req_id,
                details={"comment_id": comment_id, "author_length": len(author)}
            )
            success_message = "Your comment has been submitted successfully."

    # Retrieve persistent comments from database
    persisted_comments = CommentRepository.list_all()

    return render_template(
        "comments.html",
        comments=persisted_comments,
        validation_error=validation_error,
        success_message=success_message
    )


# ============================================================================
# PROFILE FEATURE (PERSISTENT SQLITE + URL VALIDATION + XSS PREVENTION)
# ============================================================================

@feature_bp.route("/profile", methods=["GET", "POST"])
def profile():
    """
    Profile information form and display with SQLite persistence, URL validation, and XSS prevention.
    Analyzes display_name, bio, and website fields. Enforces scheme-safe URL policy.
    """
    validation_error = None
    success_message = None
    req_id = getattr(g, "request_id", None)

    if request.method == "POST":
        raw_display_name = request.form.get("display_name", "")
        raw_bio = request.form.get("bio", "")
        raw_website = request.form.get("website", "")

        # Run Phase 5 Pipeline on display_name
        _, name_decision = process_security_pipeline(
            field_name="display_name",
            raw_value=raw_display_name,
            endpoint="/profile",
            method="POST",
            context="html_text",
            request_id=req_id
        )
        if not name_decision.should_continue:
            return render_blocked_response(name_decision)

        # Run Phase 5 Pipeline on bio
        _, bio_decision = process_security_pipeline(
            field_name="bio",
            raw_value=raw_bio,
            endpoint="/profile",
            method="POST",
            context="html_text",
            request_id=req_id
        )
        if not bio_decision.should_continue:
            return render_blocked_response(bio_decision)

        # Run Phase 5 Pipeline on website (url context)
        _, web_decision = process_security_pipeline(
            field_name="website",
            raw_value=raw_website,
            endpoint="/profile",
            method="POST",
            context="url",
            request_id=req_id
        )
        if not web_decision.should_continue:
            return render_blocked_response(web_decision)

        # Specialized URL Safety Validation
        is_url_safe, sanitized_url, url_error = validate_url(raw_website)
        if not is_url_safe:
            validation_error = url_error
        else:
            display_name = raw_display_name.strip()
            bio = raw_bio.strip()
            website = sanitized_url

            if not display_name:
                validation_error = "Display name is required."
            elif len(display_name) > 60:
                validation_error = "Display name must not exceed 60 characters."
            elif len(bio) > 300:
                validation_error = "Bio must not exceed 300 characters."
            elif len(website) > 100:
                validation_error = "Website URL must not exceed 100 characters."
            else:
                ProfileRepository.save_profile(display_name, bio, website)
                current_app.logger.info("Profile updated for: '%s' [req_id=%s]", display_name[:25], req_id)
                ApplicationEventRepository.create(
                    event_type="PROFILE_UPDATED",
                    endpoint="/profile",
                    request_id=req_id,
                    details={"name_length": len(display_name)}
                )
                success_message = "Profile updated successfully."

    # Retrieve current persistent profile
    persisted_profile = ProfileRepository.get_profile()

    return render_template(
        "profile.html",
        profile=persisted_profile,
        validation_error=validation_error,
        success_message=success_message
    )
