module CloudPrint
  class PrintJob
    attr_reader :id, :status, :error_code
    def initialize(options = {})
      @id = options[:id]
      @status = options[:status]
      @error_code = options[:error_code]
    end

    def self.find(jobid)
      job = find_by_id(jobid)
      return nil if job.nil?
      self.new(:id => job['id'], :status => job['status'], :error_code => job['errorCode'])
    end

    def self.all
      fetch_jobs.map { |j| new :id => j['id'], :status => j['status'], :error_code => j['error_code'] }
    end

    def refresh!
      job = self.class.find_by_id(id)
      @status = job['status']
      @error_code = job['errorCode']
      self
    end

    def queued?
      status == "QUEUED"
    end

    def in_progress?
      status == "IN_PROGRESS"
    end

    def done?
      status == "DONE"
    end

    def error?
      status == "ERROR"
    end

    def submitted?
      status == "SUBMITTED"
    end

  private

    def self.find_by_id(id)
      fetch_jobs.select{ |job| job['id'] == id }.first
    end

    def self.fetch_jobs
      response = CloudPrint.connection.get('/jobs') || {}
      response['jobs'] || []
    end
  end
end
