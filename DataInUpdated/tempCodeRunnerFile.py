@app.route('/documents', methods=['GET'])
def documents_list():
    if 'user_id' not in session:
        flash('Please log in to view your documents!', 'danger')
        return redirect(url_for('login'))
    
    try:
        user_id = session['user_id']
        search_query = request.args.get('search', '').strip()
        
        query = Document.query.filter_by(user_id=user_id)
        if search_query:
            query = query.filter(Document.filename.ilike(f'%{search_query}%'))
        
        documents = query.order_by(Document.created_at.desc()).all()
        total_documents = len(documents)
        
        last_activity = DocumentActivity.query.filter_by(user_id=user_id).order_by(DocumentActivity.timestamp.desc()).first()
        
        return render_template('documents.html', 
                             documents=documents, 
                             total_documents=total_documents,
                             last_activity=last_activity,
                             search_query=search_query)
    except Exception as e:
        logging.error(f"Error in documents_list: {str(e)}")
        flash('An error occurred while retrieving documents. Please try again.', 'danger')
        return redirect(url_for('home'))